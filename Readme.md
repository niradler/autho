# Autho

Autho is a local-first secret manager for humans and coding agents, rebuilt on Bun.

## Install

```bash
bun install -g autho
```

## What Ships In This Release

- Password, note, and OTP secrets (configurable algorithm and digits)
- Interactive prompt workflow via `autho` with no arguments
- Secret CRUD from the Bun CLI
- OTP code generation (RFC 6238 TOTP)
- File encryption and decryption (with `--force` overwrite guard)
- Folder encryption and decryption (with path traversal protection)
- Legacy JSON import
- Project secret mappings
- `env render`, `env sync`, and `exec`
- Short-lived secret leases with audit and revoke
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
- Audit events record access patterns without storing secret values
- Runtime state defaults to `~/.autho` and can be isolated with `AUTHO_HOME`

Current at-rest boundary for this release:

- Secret payloads, wrapped keys, and encrypted artifacts are encrypted at rest
- SQLite metadata such as names, types, timestamps, leases, and audit rows is not fully encrypted at rest
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
