---
name: autho
description: Use autho, a local-first secret manager for coding agents and humans. Trigger whenever code or a task needs an API key, token, password or OTP at runtime; to store, read or inject secrets; encrypt/decrypt files or folders; create short-lived leases; or run a command with secrets as env vars. Also trigger on mentions of "autho", AUTHO_HOME, AUTHO_MASTER_PASSWORD, or vault setup.
---

# autho

Encrypted local vault (npm `autho`, needs Bun ≥ 1.3.10). This file covers how to use it well; for exact flags run `autho help` — don't guess them.

```bash
autho --version || npm install -g autho@latest
```

## Unlocking without prompts

Agents run non-interactively. The password is taken from, in order: `--password`, `AUTHO_MASTER_PASSWORD`, the OS keychain (if the user saved it), then a TTY prompt.

- If a command hangs or asks for a password, the keychain isn't set up: ask the user, or use `AUTHO_MASTER_PASSWORD`.
- If the vault has a PIN or two-factor code, supply `AUTHO_PIN` / `AUTHO_TOTP_CODE` (or ask the user for the code; it changes every 30s).
- `--passkey` unlocks with a passkey but needs a human at the browser — not for unattended runs.
- Tests/CI: set `AUTHO_HOME` to a temp dir and `AUTHO_DISABLE_OS_SECRETS=1` so the user's real vault and keychain are never touched.

## Everyday commands

Add `--json` whenever you parse output.

```bash
autho status --json
autho secrets list --json                      # names and metadata, no values
autho secrets get --ref github --json          # returns the value — avoid unless you must
autho secrets add --name openai --type password --value "$KEY"   # types: password | note | otp
autho otp code --ref aws-otp --json
autho file encrypt --input creds.json          # → creds.json.autho; decrypt needs --force to overwrite
autho files encrypt --input ./dir              # → dir.autho-folder
```

## Injecting secrets (preferred)

Keep values out of your context, logs and shell history: inject them into the process that needs them.

```bash
autho project init --map OPENAI_API_KEY=openai --map GITHUB_TOKEN=github --force
autho exec -- npm test                          # uses the project mappings
autho exec --map OPENAI_API_KEY=openai -- node script.js
```

Least privilege for a task: create a lease, pass it to `exec`/`env render` with `--lease`, revoke when done.

```bash
LEASE=$(autho lease create --secret openai --ttl 300 --json | jq -r .id)
autho exec --lease "$LEASE" --map OPENAI_API_KEY=openai -- node task.js
autho lease revoke --lease "$LEASE"
```

`--ttl` can be omitted when the user set `defaultLeaseTtl`. For many runs in a row, `autho daemon unlock` gives a session that `daemon exec` reuses without re-deriving the key.

## Settings

- Humans: run `autho`, press `,` for Settings — paths, master password, keychain, PIN, two-factor, passkeys, recovery file, timeouts, agent defaults.
- CLI: `autho config show` (values and where each comes from), `autho config set <key> <value>`, `autho config unset <key>`.
- `autho password change` re-keys the vault; the user must type the new password — don't invent one for them.

## Rules

- Never print, echo or commit secret values; prefer `exec` over `secrets get`.
- Don't change the master password, two-factor, passkeys or recovery files unless the user asks.
- `autho audit list --json` shows what was accessed — use it to confirm a lease was used and revoked.
- On an unfamiliar error, run `autho help` and read the message; autho's errors say what is missing.
