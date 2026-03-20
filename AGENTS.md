# AGENTS.md

## Mission

Local-first secret manager for humans and AI coding agents, built on Bun.

The v0.2 release is the hardened Bun rewrite: all legacy features ported, security reviewed, and published to npm as `autho`.

Read [`.codex-tmp/plan.md`](./.codex-tmp/plan.md) before proposing architecture changes or new packages.

## Fast Context

The working tree is now the Bun rewrite:

- `apps/cli`: Bun CLI for vault, env, exec, lease, audit, import, files, daemon, and local web launch
- `apps/daemon`: local daemon for repeated unlock and exec workflows
- `apps/web`: local-only Bun web UI for unlock and secret browsing
- `packages/core`: vault domain logic and user-facing operations
- `packages/crypto`: key derivation and envelope encryption helpers
- `packages/storage`: SQLite storage and migrations
- `tests/e2e`: CLI and local-service tests that mimic real user behavior

Legacy JavaScript packages have been removed from the working tree after parity validation. If a future task needs legacy implementation details, use git history rather than recreating the old code in place.

The main reference repos already cloned into this repo are:

- `.codex-tmp/onecli`
- `.codex-tmp/agent-secrets`

Use them for patterns, not for copy-paste architecture decisions.

## Release Capabilities To Preserve

- password secrets
- OTP secrets
- notes
- file encryption and decryption
- folder encryption and decryption
- JSON import
- local-first usage
- env injection for commands
- short-lived leases with revoke
- audit visibility
- local daemon unlock flow
- local web unlock and secret browsing

## What Must Not Regress

- envelope encryption and SQLite storage
- scrypt KDF at N=2^17 (OWASP minimum for secrets at rest)
- timing-safe daemon token comparison
- Secure, HttpOnly, SameSite=Strict session cookies
- file/folder overwrite guards (require --force)
- folder decrypt path traversal validation
- Bun-first build, test, and bundle flow
- process-level user-flow tests
- prompt mode when running `autho` with no arguments
- secure env injection and `exec`
- local-only daemon and web behavior

## Rewrite Direction

Prefer this target shape:

- TypeScript monorepo
- typed core domain package
- SQLite-first storage with migrations
- modern envelope encryption
- CLI plus local daemon
- clean API and dashboard later
- agent commands for `env`, `exec`, `lease`, `revoke`, and `audit`
- optional proxy mode for non-exposure service access later

## First Files To Read

For local repo context:

- `package.json`
- `Readme.md`
- `MIGRATION.md`
- `apps/cli/src/index.ts`
- `apps/daemon/src/index.ts`
- `apps/web/src/index.ts`
- `packages/core/src/index.ts`
- `packages/crypto/src/index.ts`
- `packages/storage/src/index.ts`
- `tests/e2e/cli.test.ts`
- `.codex-tmp/plan.md`

For reference patterns:

- `.codex-tmp/onecli/README.md`
- `.codex-tmp/onecli/docs/nanoclaw-integration.md`
- `.codex-tmp/onecli/apps/gateway/src/inject.rs`
- `.codex-tmp/agent-secrets/README.md`
- `.codex-tmp/agent-secrets/cmd/secrets/env.go`
- `.codex-tmp/agent-secrets/cmd/secrets/exec.go`
- `.codex-tmp/agent-secrets/AGENTS.md`

## Fast Explore Commands

Use these first:

```powershell
rg --files
Get-Content package.json
Get-Content Readme.md
Get-Content MIGRATION.md
Get-ChildItem apps,packages,tests -Recurse -Depth 3
```

Useful targeted reads:

```powershell
Get-Content apps\cli\src\index.ts
Get-Content packages\core\src\index.ts
Get-Content packages\crypto\src\index.ts
Get-Content packages\storage\src\index.ts
Get-Content tests\e2e\cli.test.ts
Get-Content .codex-tmp\plan.md
```

Reference repo checks:

```powershell
Get-Content .codex-tmp\onecli\README.md
Get-Content .codex-tmp\agent-secrets\README.md
Get-Content .codex-tmp\agent-secrets\cmd\secrets\env.go
Get-Content .codex-tmp\agent-secrets\cmd\secrets\exec.go
```

## Working Rules For Future Agents

- Preserve feature parity before deleting or reshaping user-visible flows.
- Do not weaken the current crypto, unlock, or audit model for convenience.
- Prefer small migration-safe slices over a big-bang rewrite.
- Keep human vault flows and agent-secret flows clearly separated.
- For agent features, default to least privilege, TTLs, audit, and revocation.
- Prefer non-exposure patterns when possible: proxy or broker over raw secret return.
- If architecture direction changes materially, update `.codex-tmp/plan.md` first.
- If new reference repos are introduced, record why they matter and what pattern they contribute.
- Treat Bun compatibility as a release requirement, not a secondary convenience.

## npm Package

The CLI is published as `autho` on npm from `apps/cli/`. Build with `bun run build:cli`, pack/publish from `apps/cli/`.

## Known TODOs

- File DEK AAD is static (`autho:file:dek`) — should be per-file for stronger binding (format-breaking, deferred to v0.3)

## Expected Deliverables In Future Passes

Depending on the task, future work should usually update one or more of:

- `.codex-tmp/plan.md`
- release or migration docs
- typed packages for the new core
- tests proving parity or safer agent behavior
- packaging or release automation

## Notes

- `.codex-tmp` holds reference repos and the active rewrite plan.
- Use ORC CLI for task and knowledge tracking when it is installed in the environment; do not block work on ORC availability.
- The current repo may be dirty. Do not revert unrelated user changes.
- This project should stay easy for both humans and coding agents to operate safely.
- when we clone on other machine the codex-tmp is nto avilable
- update readme.md file when needed to align witht he project, keep it clean and sturctured.
