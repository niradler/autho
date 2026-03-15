# AGENTS.md

## Mission

This repository is being rewritten from a legacy secret vault into a modern local-first secret platform for humans and AI coding agents.

The rewrite must preserve existing Autho capabilities while adding:

- secure env injection for commands and agent tasks
- short-lived secret leases
- audit and revocation
- policy-scoped agent access
- optional proxy or gateway flows so agents can use services without seeing real API keys

Read [`plan.md`](./plan.md) before proposing architecture changes or new packages.

## Fast Context

The current codebase is an old JavaScript pnpm workspace with these legacy surfaces:

- `packages/cli`: interactive CLI and file or folder encryption commands
- `packages/sdk`: secret CRUD, OTP logic, DB wrapper, crypto helpers
- `packages/server`: minimal Express server and EJS UI
- `packages/models`: Joi schema for secret records
- `packages/shared`: config and logging

The main rewrite references already cloned into this repo are:

- `.codex-tmp/onecli`
- `.codex-tmp/agent-secrets`

Use them for patterns, not for copy-paste architecture decisions.

## Legacy Capabilities To Preserve

- password secrets
- OTP secrets
- notes
- file encryption and decryption
- folder encryption and decryption
- JSON import
- local-first usage

## What Is Wrong Today

- crypto design is weak
- the master password hash doubles as the encryption key
- storage is tied to `conf`
- server auth sends master credentials in headers
- no meaningful tests

Future work should improve these areas, not reinforce them.

## Rewrite Direction

Prefer this target shape:

- TypeScript monorepo
- typed core domain package
- SQLite-first storage with migrations
- modern envelope encryption
- CLI plus local daemon
- clean API and dashboard
- agent commands for `env`, `exec`, `lease`, `revoke`, and `audit`
- optional proxy mode for non-exposure service access

## First Files To Read

For local repo context:

- `package.json`
- `Readme.md`
- `packages/cli/bin.js`
- `packages/cli/app.js`
- `packages/sdk/cipher.js`
- `packages/sdk/secrets.js`
- `packages/sdk/otp.js`
- `packages/server/middlewares/auth.js`
- `plan.md`

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
Get-ChildItem packages -Recurse -Depth 2
```

Useful targeted reads:

```powershell
Get-Content packages\cli\bin.js
Get-Content packages\sdk\cipher.js
Get-Content packages\sdk\secrets.js
Get-Content packages\server\middlewares\auth.js
Get-Content plan.md
```

Reference repo checks:

```powershell
Get-Content .codex-tmp\onecli\README.md
Get-Content .codex-tmp\agent-secrets\README.md
Get-Content .codex-tmp\agent-secrets\cmd\secrets\env.go
Get-Content .codex-tmp\agent-secrets\cmd\secrets\exec.go
```

## Working Rules For Future Agents

- Preserve feature parity before deleting old capabilities.
- Do not keep the existing crypto or auth model just because it exists.
- Prefer small migration-safe slices over a big-bang rewrite.
- Keep human vault flows and agent-secret flows clearly separated.
- For agent features, default to least privilege, TTLs, audit, and revocation.
- Prefer non-exposure patterns when possible: proxy or broker over raw secret return.
- If architecture direction changes materially, update `plan.md` first.
- If new reference repos are introduced, record why they matter and what pattern they contribute.

## Expected Deliverables In Future Passes

Depending on the task, future work should usually update one or more of:

- `plan.md`
- architecture docs
- migration docs
- typed packages for the new core
- tests proving parity or safer agent behavior

## Notes

- `.codex-tmp` is for inspection only.
- The current repo may be dirty. Do not revert unrelated user changes.
- This project should end up easier for both humans and coding agents to operate safely.
