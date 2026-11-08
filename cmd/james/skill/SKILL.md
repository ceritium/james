---
name: james
description: Run commands that need secrets (API keys, tokens, passwords, credentials, SSH keys for git or ssh) through james, which asks the user for Touch ID and lends 1Password secrets for a limited time. Use whenever a command needs a secret in its environment, a tool fails for missing credentials, or you are about to reach for `op`, a `.env` file, or ask the user to paste a secret.
---

# Secrets through james

The user keeps secrets in 1Password. They reach a command only through `james`, which shows a Touch ID prompt with your command, folder and reason, then sets the secrets as environment variables for that command.

## Run a command with secrets

1. Find a profile: `james profiles` lists each profile and the variables it sets.
2. Run through it:
   ```sh
   james run -p <profile> --reason "<why, one line>" -- <command> [args...]
   ```
   The first run prompts the user. Later runs in this session reuse the grant until it expires, without prompting.
3. Several commands coming? Approve once up front with `james bond <profile> --reason "<why>"`.

Profiles with SSH keys set `SSH_AUTH_SOCK` for the command, so `james run -p <profile> -- git push` or `-- ssh host` signs with the profile's key. The key never leaves james.

Each `james run` covers one command. Variables do not persist in your shell, so wrap every command that needs them, including `sh -c '...'` pipelines.

## Rules

- Never use `op`, read `.env` files or keychains, or ask the user to paste a secret.
- No profile fits? Tell the user which variables are needed and for what, so they can add a profile to `~/.config/james/config.yaml`. Don't edit that file yourself.
- `james run --secret VAR=op://... -- <command>` is for one-off refs the user names explicitly. Don't use it otherwise.
- Never print, log, or write a secret value, and don't echo the variables to check them. To confirm a value arrived, check only that it is non-empty: `sh -c 'test -n "$VAR"'`.
- If the user denies the prompt, stop and ask. Don't retry or look for another route.

## Errors

- `unknown profile`: run `james profiles` and pick an existing one, or ask the user.
- `request denied`: the user said no; ask before doing anything else that needs secrets.
- `Touch ID unavailable`: the Mac may be in clamshell mode; tell the user.
- `james daemon is not running` or `a different james build`: tell the user; do not start the daemon yourself.
