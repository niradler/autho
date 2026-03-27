# autho

Local-first secret manager for humans and coding agents, rebuilt on [Bun](https://bun.sh).

Autho stores secrets in an encrypted SQLite vault on your machine. No cloud, no sync, no account. Secrets are envelope-encrypted with AES-256-GCM and protected by a master password via scrypt KDF.

## Install

```bash
bun install -g autho
```

Requires **Bun 1.3.10+**.

## Quick Start

```bash
# Create a vault
autho init --password "correct horse battery staple"

# Add a secret
autho secrets add --password "..." --name github --type password --value ghp_xxx --username octocat --url https://github.com

# Read it back
autho secrets get --password "..." --ref github --json

# Generate an OTP code
autho otp code --password "..." --ref my-totp --json
```

Run `autho init` to save your master password to the native OS secret store (macOS Keychain, Linux Secret Service, Windows Credential Manager). After that, all commands unlock silently without prompting.

You can also set `AUTHO_MASTER_PASSWORD` to avoid passing `--password` on every call, or set `AUTHO_DISABLE_OS_SECRETS=1` to opt out of OS secret storage.

## Features

- **Secret CRUD** — password, note, and OTP types with metadata
- **OTP generation** — RFC 6238 TOTP with configurable algorithm and digits
- **File encryption** — encrypt/decrypt individual files or entire folders
- **Env injection** — render secrets as env vars, write `.env` files, or inject into subprocesses
- **Project mappings** — define `ENV_NAME=secretRef` maps in a project config file
- **Leases** — time-limited, revocable access tokens scoped to specific secrets
- **Audit trail** — every vault operation is logged with timestamps and metadata
- **Legacy import** — migrate from JSON backup files
- **Interactive mode** — run `autho` with no arguments for a guided prompt
- **Local daemon** — unlock once, run many commands without re-entering your password
- **Local web UI** — browser-based secret browsing on localhost

## Commands

```
autho init --password <value> [--vault <path>]
autho status [--password <value>] [--vault <path>] [--json]
autho secrets add --password <value> --name <name> --type <password|note|otp> --value <value> [options]
autho secrets list --password <value> [--vault <path>] [--json]
autho secrets get --password <value> --ref <name-or-id> [--vault <path>] [--json]
autho secrets rm --password <value> --ref <name-or-id> [--vault <path>] [--json]
autho otp code --password <value> --ref <name-or-id> [--vault <path>] [--json]
autho lease create --password <value> --secret <ref> --ttl <seconds> [--name <value>] [--json]
autho lease revoke --password <value> --lease <id> [--json]
autho env render --password <value> --map <ENV=ref> [--project-file <path>] [--lease <id>] [--json]
autho env sync --password <value> --map <ENV=ref> [--output <path>] [--force] [--ttl <seconds>] [--json]
autho exec --password <value> --map <ENV=ref> [--lease <id>] -- <command>
autho file encrypt --password <value> --input <path> [--output <path>] [--force] [--json]
autho file decrypt --password <value> --input <path> [--output <path>] [--force] [--json]
autho files encrypt --password <value> --input <path> [--output <path>] [--force] [--json]
autho files decrypt --password <value> --input <path> [--output <path>] [--force] [--json]
autho import legacy --password <value> --file <path> [--no-skip-existing] [--json]
autho audit list --password <value> [--limit <number>] [--json]
autho project init --map <ENV=ref> [--output <path>] [--force] [--json]
autho daemon serve [--vault <path>] [--port <value>]
autho daemon status [--state-file <path>] [--json]
autho daemon unlock --password <value> [--ttl <seconds>] [--state-file <path>] [--json]
autho daemon lock --session <id> [--state-file <path>] [--json]
autho daemon stop [--state-file <path>] [--json]
autho daemon env render --session <id> --map <ENV=ref> [--project-file <path>] [--json]
autho daemon exec --session <id> --map <ENV=ref> [--project-file <path>] -- <command>
```

Run `autho help` for the full reference.

## Security Model

- Master password derives a key-encryption key via **scrypt** (N=2^17, r=8, p=1)
- Each vault gets a random 256-bit root key
- Secret payloads use **AES-256-GCM** envelope encryption with per-secret DEKs
- File and folder artifacts use the same envelope encryption scheme
- SQLite vault files are hardened to `0600` permissions
- Daemon auth tokens use OS secret storage when available (falls back to file)
- Audit events record access patterns without storing secret values

## Storage

By default, Autho stores everything under `~/.autho/`:

- `vault.db` — encrypted SQLite vault
- `project.json` — project env mappings
- `daemon.json` — daemon state

Override with `AUTHO_HOME` or `--vault <path>`.

## Agent Usage

Autho is designed for coding agents that need secrets at runtime:

```bash
# Set password once
export AUTHO_MASTER_PASSWORD="..."

# Agent creates a scoped, time-limited lease
autho lease create --secret github --secret openai --ttl 300 --json

# Agent runs with injected env
autho exec --lease <id> --map GITHUB_TOKEN=github --map OPENAI_KEY=openai -- node build.js

# Lease auto-expires or can be revoked
autho lease revoke --lease <id>
```

## License

MIT
