# james

Lends secrets from 1Password to coding agents for a limited time, approved with Touch ID.

You define profiles: named sets of secrets. An agent asks for a profile, you approve it with your fingerprint, and commands that agent session runs get those secrets as environment variables until the grant expires. Nothing else on the machine gets access to your 1Password account.

macOS on Apple Silicon only. Requires the 1Password desktop app with **Settings → Developer → Integrate with other apps** enabled.

## Install

```sh
go build -o ~/.local/bin/james ./cmd/james
```

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
```

## Use

```sh
james run -p restic -- restic backup ~/Documents   # prompts once, then reuses the grant
james bond deploy --reason "deploy staging"        # approve up front
james run --secret TOKEN=op://Personal/x/token -- ./script   # one-off; prompts every time
james list                                         # active grants
james revoke deploy                                # or --all
james profiles
```

## How it works

- A per-user daemon is the only process that talks to 1Password. The CLI starts it on demand.
- The daemon accepts only clients that are the exact same signed `james` binary, checked through the socket's audit token and code signature, not the PID.
- A grant binds to the nearest ancestor process named in `anchors` (PID plus start time). It ends when it expires, when it is revoked, or when that agent process exits. Without an agent ancestor, every run prompts.
- One-off `--secret` refs always prompt and are never reused.
- Every approval and use is appended to `~/Library/Logs/james/audit.jsonl`, without values.

## Limits

- The child process receives secrets as environment variables and can do anything with them.
- Any process the agent spawns during a grant can use that profile.
- Grants live in daemon memory; they are lost when the daemon restarts.
- Each build has its own code signature. Running a different `james` build stops the current daemon and its grants, so keep a single install.
