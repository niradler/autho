# Autho

Autho is a local-first secret manager for humans and coding agents, rebuilt on Bun.

## Install

```bash
bun install -g autho
```

## What Ships In This Release

- Password, note, and OTP secrets (configurable algorithm and digits)
- Terminal UI via `autho` with no arguments: search, reveal, copy, mouse selection, command palette (Linux, macOS, Windows)
- Passkey and hardware security key unlock (WebAuthn PRF / FIDO2 hmac-secret)
- One Settings page in the TUI for paths, unlock methods, timeouts and agent defaults
- Master password change without re-encrypting secrets
- Secret CRUD from the Bun CLI
- OTP code generation (RFC 6238 TOTP)
- File encryption and decryption (with `--force` overwrite guard)
- Folder encryption and decryption (with path traversal protection)
- Legacy JSON import
- Project secret mappings
- `env render`, `env sync`, and `exec`
- Short-lived secret leases with audit and revoke
- Secret linking: keep a login's OTP, recovery codes or keys together under one primary secret
- Vault seal: edits made to the SQLite file outside autho are detected and block agent access
- Local daemon unlock flow for repeated agent tasks
- Local-only Bun web UI for unlock and secret browsing
- Native OS secret store integration (macOS Keychain, Linux Secret Service, Windows Credential Manager)

## Security Model

- Master password derives a key-encryption key via **scrypt** (N=2^17, r=8, p=1, OWASP minimum)
- Each vault gets a random 256-bit root key
- Secret payloads and file artifacts use **AES-256-GCM** envelope encryption with per-secret DEKs
- Daemon bearer token comparison uses **timing-safe equality**
- Web session cookies set **HttpOnly**, **SameSite=Strict**, and **Secure** flags
- File and folder decrypt operations include **overwrite guards** (require `--force`)
- Folder decryption validates paths against **directory traversal**
- SQLite vault files are hardened to `0600` permissions
- Local daemon auth tokens use OS secret storage when available (falls back to file)
- Master password can be saved to OS secret store via setup wizard (`autho init`) — no repeated prompts
- PIN is a local machine gate stored in the OS keychain — it does not travel with the vault file and provides no cryptographic protection of vault data
- Passkeys and security keys wrap the root key with a key derived (HKDF-SHA256) from the authenticator's PRF output; the PRF value is never stored, and user verification (biometric or PIN) is required
- Copied secrets are cleared from the clipboard after 30 seconds, only if the clipboard still holds them — also after the TUI exits
- Audit events record access patterns without storing secret values
- The vault is **sealed**: an HMAC (keyed from the root key) covers secrets, links, leases and settings. Any change made without the key stops `env`, `exec` and lease reads until `autho vault reseal`; revoking a lease always works
- `env` and `exec` inject an OTP secret's current code, never its seed
- Runtime state defaults to `~/.autho` and can be isolated with `AUTHO_HOME`

Current at-rest boundary for this release:

- Secret payloads, wrapped keys, and encrypted artifacts are encrypted at rest
- SQLite metadata such as names, types, timestamps, leases, and audit rows is not fully encrypted at rest (it is sealed against edits, except audit rows)
- Swapping in an older copy of the whole vault file is caught using the newest seal autho has seen, kept in the OS keychain; with `AUTHO_DISABLE_OS_SECRETS=1` or no keychain, it goes unnoticed
- If the OS secret store is unavailable, the daemon token falls back to the local state file
- Set `AUTHO_DISABLE_OS_SECRETS=1` to opt out of all OS secret store usage

## Requirements

- Bun `1.3.10` or newer
- Windows, macOS, or Linux

## Quick Start

```bash
bun install
bun run hooks:install
bun run autho -- init --password "correct horse battery staple"
```

The setup wizard will guide you through optional security features — save your master password to the OS keychain, set a local PIN, or enable TOTP. After saving to the keychain, all commands unlock silently without prompting.

To opt out of OS secret store usage: `AUTHO_DISABLE_OS_SECRETS=1`

By default, Autho stores runtime state in `~/.autho`. For tests, CI, or isolated environments you can override that with `AUTHO_HOME`.

Run the interactive prompt:

```bash
bun run autho
```

Add and read a secret:

```bash
bun run autho -- secrets add --password "correct horse battery staple" --name github --type password --value ghp_example --username octocat --url https://github.com
bun run autho -- secrets get --password "correct horse battery staple" --ref github --json
```

Generate an OTP code:

```bash
bun run autho -- otp code --password "correct horse battery staple" --ref my-otp --json
```

Encrypt and decrypt a file:

```bash
bun run autho -- file encrypt --password "correct horse battery staple" --input ./secret.txt
bun run autho -- file decrypt --password "correct horse battery staple" --input ./secret.txt.autho
```

Create a project mapping and render env vars:

```bash
bun run autho -- project init --map OPENAI_API_KEY=openai --map GITHUB_TOKEN=github --force
bun run autho -- env render --password "correct horse battery staple" --project-file ./.autho/project.json --json
```

Run a command with injected env vars:

```bash
bun run autho -- exec --password "correct horse battery staple" --project-file ./.autho/project.json -- bun -e "console.log(process.env.GITHUB_TOKEN)"
```

Start the daemon:

```bash
bun run daemon
```

Start the local web UI:

```bash
bun run web
```

## Terminal UI

Run `autho` with no arguments to open the TUI.

| Key | Action |
| --- | --- |
| `/` | Search secrets |
| `↑↓` `j/k` `PgUp/PgDn` `g/G` | Move |
| `enter` | Open the selected secret; in the detail view, copy its value |
| `s` / `space` | Reveal or hide the value |
| `c` | Copy the password, note or current OTP code |
| `u` | Copy the username |
| `w` / `o` | Copy / open the URL |
| `n` / `e` / `d` | New / edit / delete (`a` in the delete prompt also deletes linked secrets) |
| `L` | Link or unlink secrets under the selected one |
| `t` | Show and copy the linked OTP's code |
| `,` | Settings |
| `q` | Quit |
| `ctrl+k` / `?` | Command palette: every action on the current screen, plus jump to any secret |
| `ctrl+l` | Lock now |
| `ctrl+c` | Copy the mouse selection or focused value; press again to quit |
| `ctrl+p` | (unlock screen) Unlock with a passkey or security key |

- Drag with the mouse to select any text, including a revealed value, then press `ctrl+c` to copy it.
- Copying works without extra setup on Windows (`clip`/PowerShell), macOS (`pbcopy`), Wayland (`wl-copy`) and X11 (`xclip`/`xsel`), and falls back to OSC 52 over SSH.
- Password inputs are always masked; `ctrl+r` shows what you typed.
- When editing a secret, `ctrl+r` loads the stored value so you can see and change it; leaving the field empty keeps it.

- A value revealed in the editor hides again after the reveal timeout, when you leave the field, or when the palette opens.
- A secret's linked secrets show on its page; the palette has "Go to" for each one.

## Settings

Press `,` in the TUI (or pick Settings in the palette) for one page with everything configurable:

| Section | What you can do |
| --- | --- |
| Storage | See and copy the vault, config, project and daemon paths; point autho at another vault folder |
| Security | Change the master password, remember it in the OS keychain, set a PIN, turn two-factor codes on or off, add or remove passkeys and security keys, create or revoke the recovery file |
| Behaviour | Reveal timeout, clipboard clear, auto-lock, generated password length and symbols, mouse |
| Agents & services | Default lease TTL, daemon session TTL, web UI port |
| About | Version, runtime, OS secret store |

Security changes ask for the master password (and two-factor code) once per visit; the handle is dropped when you leave Settings. Changing the vault folder only changes the setting — move `vault.db` yourself, then restart autho.

The same settings work from the CLI and are saved in `config.json` (`autho config path`):

```bash
autho config show                     # every setting, its value and where it comes from
autho config set revealSeconds 60
autho config unset revealSeconds      # back to the default
autho password change                 # prompts; or --new-password / AUTHO_NEW_MASTER_PASSWORD
```

Environment variables still win over `config.json`: `AUTHO_TUI_REVEAL_SECONDS`, `AUTHO_CLIPBOARD_CLEAR_SECONDS`, `AUTHO_TUI_LOCK_SECONDS` (`0` disables a timer). `autho config show` names the variable when one is in effect.

## Passkeys And Security Keys

Unlock with Touch ID, Windows Hello, a phone passkey, or a FIDO2 key such as a YubiKey:

```bash
autho passkey add --label yubikey     # opens a one-time page on http://localhost
autho secrets list --passkey          # any command: unlock with the passkey
autho passkey list
autho passkey remove yubikey
```

How it works: WebAuthn runs on a single-use localhost page (random token, Host/Origin checks, strict CSP). The authenticator's PRF extension (hmac-secret) returns a 32-byte value that only it can produce. Autho derives a key from it and wraps the vault root key, the same way the recovery token does. Your master password keeps working.

Notes:

- A passkey unlock replaces the password, PIN and TOTP prompts, because the authenticator already required a biometric or PIN.
- PRF support is needed: recent Chrome or Edge (Windows Hello included), Safari 18+ on macOS, and most FIDO2 security keys. Unsupported setups get a clear error, and nothing is saved.
- Credentials are bound to `localhost` and to this vault; a passkey must be added on each vault separately.

## Build And Release

Build Bun bundles:

```bash
bun run build
```

Build standalone compiled binaries:

```bash
bun run build:compile
```

Run the full quality gate:

```bash
bun run check
```

### npm Publish

The CLI is published as `autho` on npm. To publish a new version:

```bash
bun run build:cli
cd apps/cli && npm publish
```

The package includes only `dist/autho.js` and `README.md` (~15 KB tarball).

## Upgrading

If you already have a vault from a previous version, just update and run any command:

```bash
bun install -g autho@latest
autho secrets list --password "..."
```

The setup wizard will offer to save your master password to the OS keychain. After that, all commands unlock silently.

A vault from before the vault seal is sealed the first time it is unlocked with the master password, typed or saved in the keychain (passkey and recovery-file unlocks don't seal it). Until then `env`, `exec` and leases refuse to run; `autho vault verify` shows the state.

See [MIGRATION.md](./MIGRATION.md) for full details and legacy import instructions.

## Testing

The Bun end-to-end suite covers the main user flows from real process boundaries:

- vault init and status
- prompt mode create and list
- secret CRUD
- OTP generation
- project mapping, env render or sync, and exec
- lease create and revoke
- audit inspection
- legacy JSON import
- file and folder crypto
- daemon-backed unlock and exec
- local web unlock and secret APIs

Unit and UI tests cover the TUI (masking, reveal, copy, ctrl+c, mouse selection, palette, passkey unlock), clipboard backends, passkey key wrapping, and the passkey ceremony server.

Run it with:

```bash
bun test
```

## Repo Layout

- `apps/cli`: Bun CLI
- `apps/daemon`: local daemon
- `apps/web`: local Bun web UI
- `packages/core`: domain and vault logic
- `packages/crypto`: KDF and encryption helpers
- `packages/storage`: SQLite access and migrations
- `tests/e2e`: process-level user-flow tests

## Agent Usage

Autho is designed for coding agents that need secrets at runtime:

```bash
# After saving to OS keychain via `autho init` — no env var needed
autho lease create --secret github --secret openai --ttl 300 --json
autho exec --lease <id> --map GITHUB_TOKEN=github --map OPENAI_KEY=openai -- node build.js
autho lease revoke --lease <id>
```

A lease also covers the secrets linked to its secrets, read live: link a new OTP to `github`
mid-task and the agent can read it right away; unlink it and access stops. Use `--no-links` to
lease only the named secrets, and `lease show` to see what a lease can read now.

```bash
autho link github github-otp              # show github-otp on github's page
autho secrets get --ref github --links
autho lease show --lease <id>
autho unlink github github-otp
autho secrets rm --ref github --with-linked   # also delete linked secrets no other secret links to
```

If the vault file is edited outside autho, `env`, `exec` and writes stop with an error:

```bash
autho vault verify            # what changed (exit code 2 when tampered)
autho vault reseal            # undo the changes, revoke all leases, re-sign
autho vault reseal --accept   # the change was yours: re-sign as is
```

`reseal` puts renamed, edited or deleted rows back from the copies the seal signed, and drops rows that were added. If the seal's own list of rows was edited too, it only drops added or changed links and leases and lists the rest for you to check. Copies are kept from the first write after upgrading.

If the OS secret store is unavailable (headless CI, Docker), fall back to the env var:

```bash
export AUTHO_MASTER_PASSWORD="..."
```

Store arbitrary named secrets in the OS secret store directly:

```bash
autho os-secrets set --name my-token --value ghp_xxx
autho os-secrets get --name my-token
autho os-secrets delete --name my-token
```

## Current Scope

This release is intended to be stable for local-first Bun usage and parity with the legacy vault workflows. Planned future work includes proxy mode, richer agent policy management, and a fuller dashboard.
