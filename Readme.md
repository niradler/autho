# Autho

Autho is a local-first secret manager for humans and coding agents, rebuilt on Bun.

This release is the Bun migration and legacy-parity cut. It keeps the existing core workflows, hardens the local vault design, and ships the current Bun CLI, daemon, and local web surface. It does not add new platform scope beyond parity and release hardening.

## What Ships In This Release

- Password, note, and OTP secrets
- Interactive prompt workflow via `autho` with no arguments
- Secret CRUD from the Bun CLI
- OTP code generation
- File encryption and decryption
- Folder encryption and decryption
- Legacy JSON import
- Project secret mappings
- `env render`, `env sync`, and `exec`
- Short-lived secret leases with audit and revoke
- Local daemon unlock flow for repeated agent tasks
- Local-only Bun web UI for unlock and secret browsing

## Security Model

- The master password is used only to derive a key-encryption key with `scrypt`
- Each vault gets a random root key
- Secret payloads and file artifacts use AES-256-GCM envelope encryption
- The vault uses SQLite instead of the old `conf` store
- Local daemon auth tokens are stored with `Bun.secrets` when the OS secret store is available
- Audit events record access without storing secret values
- Runtime state defaults to `~/.autho` and can be isolated with `AUTHO_HOME`

Current at-rest boundary for this release:

- Secret payloads, wrapped keys, and encrypted artifacts are encrypted at rest
- SQLite metadata such as names, types, timestamps, leases, and audit rows is not fully encrypted at rest
- If the OS secret store is unavailable, the daemon token falls back to the local state file

## Requirements

- Bun `1.3.10` or newer
- Windows, macOS, or Linux

## Quick Start

```bash
bun install
bun run hooks:install
bun run autho -- init --password "correct horse battery staple"
```

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

## Migration

This Bun release supports migration from legacy JSON backups and documented manual migration from older `conf`-based installs. Direct in-product `conf` store migration is intentionally not part of this release.

See [MIGRATION.md](./MIGRATION.md) for the supported process and the expected JSON format.

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

## Current Scope

This release is intended to be stable for local-first Bun usage and parity with the legacy vault workflows. Planned future work such as proxy mode, richer agent policy management, and a fuller dashboard remains tracked in [plan.md](./plan.md) and is not part of this release cut.
