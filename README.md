# james

Lends secrets from 1Password to coding agents for a limited time, approved with Touch ID.

You define profiles: named sets of secrets. An agent asks for a profile, you approve it with your fingerprint, and commands that agent session runs get those secrets as environment variables until the grant expires. Nothing else on the machine gets access to your 1Password account.

macOS on Apple Silicon only. Requires the 1Password desktop app with **Settings → Developer → Integrate with other apps** enabled.

## Install

```sh
make install          # builds, signs with the hardened runtime, installs to ~/.local/bin
# or with Nix: nix build github:ceritium/james (package.nix; the flake's nixpkgs needs sandbox = false)
james skill-install   # teaches Claude Code to use james; --dir for other agents
```

Run `james daemon` as a LaunchAgent with `KeepAlive` (nix-config does it in `home/james.nix`), or by hand in a terminal.

## Configure

`~/.config/james/config.yaml` (must be `chmod 600`):

```yaml
providers:
  1password:
    default_account: YOUR_ACCOUNT_UUID   # or sign-in address

anchors: [claude]   # agent processes a grant binds to

profiles:
  restic:
    ttl: 1h
    secrets:
      RESTIC_PASSWORD: op://Personal/restic/password
  deploy:
    ttl: 30m
    secrets:
      CLOUDFLARE_API_TOKEN: op://scripts/cloudflare/credential
      AWS_SECRET_ACCESS_KEY:
        ref: op://Work/aws/secret
        account: work.1password.com
  github:
    ttl: 2h
    ssh_keys:
      - op://Personal/GitHub SSH/private key?ssh-format=openssh
```

Profiles with `ssh_keys` set `SSH_AUTH_SOCK` to the daemon's SSH agent. The agent signs only for processes under an agent session holding a grant for that profile; to everything else it is empty. Keys never leave the daemon.

## Use

```sh
james run -p restic -- restic backup ~/Documents   # prompts once, then reuses the grant
james run -p github -- git push                    # SSH keys through the daemon's agent
james bond deploy --reason "deploy staging"        # approve up front
james run --secret TOKEN=op://Personal/x/token -- ./script   # one-off; prompts every time
james list                                         # active grants
james revoke deploy                                # or --all
james profiles
james log -f                                       # audit log; -p PROFILE, --since 2h, --json
```

## How it works

- A per-user daemon is the only process that talks to 1Password. Run it with a LaunchAgent (`james daemon`, `KeepAlive`); the CLI never starts it, so it never inherits an agent's environment.
- The daemon accepts only clients that are the exact same signed `james` binary, checked through the socket's audit token and code signature, not the PID.
- A grant binds to the nearest ancestor process named in `anchors` (PID plus start time). It ends when it expires, when it is revoked, or when that agent process exits. Without an agent ancestor, every run prompts.
- One-off `--secret` refs always prompt and are never reused.
- Every approval and use is appended to `~/Library/Logs/james/audit.jsonl`, without values.

## Limits

- SSH private keys are fetched from 1Password for each signature and wiped afterwards; only public keys are cached. Wiping RSA keys is best effort in Go.
- Build with `make install`: a plain `go build` lacks the hardened runtime, so root could read secrets from daemon memory (the daemon logs a warning).
- The child process receives secrets as environment variables and can do anything with them. `james run` drops variables that load extra code into it (`NODE_OPTIONS`, `BASH_ENV`, `DYLD_*`, `GIT_SSH_COMMAND`…).
- Any process the agent spawns during a grant can use that profile.
- Grants live in daemon memory; they are lost when the daemon restarts.
- Each build has its own code signature, and the CLI refuses a daemon from another build. Keep a single install.
