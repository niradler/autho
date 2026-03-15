# Autho Rewrite Plan

## Intent

Rewrite Autho from the current legacy JavaScript monorepo into a modern, typed, secure platform that:

- preserves the existing vault capabilities
- upgrades the storage, crypto, CLI, and server foundations
- adds first-class support for AI coding agents and agent runtimes
- allows secrets to be injected into commands and services without exposing raw credentials unless explicitly required

This plan is based on the current Autho codebase plus patterns reviewed from:

- `onecli`: gateway-based secret injection so agents do not need real API keys
- `agent-secrets`: local encrypted store, leases, TTLs, audit, env injection, and command execution workflows

## Current Autho Capabilities To Preserve

- Local encrypted secret storage via `conf`
- Secret types: `password`, `otp`, `note`
- CLI prompt workflow for create, read, delete, list
- OTP generation for TOTP secrets
- File encryption and decryption
- Folder encryption and decryption
- Secret import from JSON backup
- Minimal Express server and web UI
- Support for a master password or password hash
- Optional per-secret extra protection flow

## Current Technical Problems

- Crypto is not modern enough for a rewrite target.
- The master password hash is reused as the encryption key.
- There is no durable audit model.
- There is no lease or revocation model for agent access.
- The API auth model is weak and based on passing master secrets in headers.
- Storage is tied to `conf`, which is hard to evolve, migrate, and query.
- The codebase is untyped, lightly structured, and has no meaningful test coverage.
- The current server is not designed for multi-client, multi-agent, or policy-based access.
- Secret exposure boundaries are unclear: agents can end up seeing plaintext where a brokered flow would be safer.

## Rewrite Goals

- Move to TypeScript across product surfaces.
- Separate core domain logic from CLI, API, UI, and agent runtimes.
- Replace the current storage model with a migration-friendly database.
- Replace ad hoc crypto with a modern envelope-encryption design.
- Support both human workflows and agent workflows.
- Keep local-first operation possible.
- Add a secure way to inject secrets into commands as environment variables.
- Add a safer proxy or broker mode so agents can call services without holding the real API key.
- Add session leases, TTLs, audit logs, and emergency revocation.
- Keep the product simple enough to ship incrementally instead of attempting a full platform rewrite in one step.

## Product Direction

Autho v2 should be a local-first secret platform for humans and agents.

It should support three access modes:

- Vault mode: users manage OTPs, passwords, notes, and encrypted files.
- Agent env mode: short-lived secrets are injected into process environments for builds, tests, deploys, and coding agents.
- Agent gateway mode: Autho brokers outbound service access and injects credentials at the edge, so the agent never receives the real key.

## Recommended Architecture

## Monorepo Shape

- `apps/cli`: end-user CLI for vault, env, exec, lease, audit, import, and migration commands
- `apps/daemon`: local background service exposing a Unix socket on Unix and named pipe on Windows
- `apps/api`: optional HTTP API for local or self-hosted dashboard access
- `apps/web`: dashboard for secrets, agents, sessions, policies, audit, and setup
- `packages/core`: domain services, use cases, validation, policies
- `packages/crypto`: key derivation, encryption, signatures, file crypto helpers
- `packages/storage`: database access, migrations, repositories
- `packages/agent-sdk`: small SDK for agents, CLIs, and local tooling
- `packages/proxy`: outbound proxy or injection engine for service brokering
- `packages/shared`: logging, config loading, redaction, telemetry helpers

## Technology Choices

- Runtime: Bun as the primary runtime for local development, tests, and bundling
- Language: TypeScript with strict mode
- Package manager: Bun workspaces
- Workspace task runner: Bun workspaces plus root scripts
- Bundling: `Bun.build` for cross-platform CLI packaging and small local daemon bundles
- CLI: typed command modules with machine-readable JSON output and human-friendly defaults
- API: Fastify for local and self-hosted APIs
- Web: Next.js App Router or a typed React SPA if the dashboard remains secondary
- Database: SQLite for local-first mode, PostgreSQL only if a later team or hosted mode is added
- ORM or query layer: Drizzle ORM
- Validation: Zod
- Tests: Bun test for unit and integration, CLI-driven end-to-end tests that mimic user behavior, Playwright later for critical UI flows

## Security Model

## Key Management

- Derive a key-encryption key from the master password using Argon2id.
- Generate a random vault root key during setup.
- Encrypt the vault root key with the derived key.
- Encrypt each secret or file payload with its own data encryption key.
- Store only encrypted payloads and encrypted data keys in the database.

## Encryption

- Use XChaCha20-Poly1305 or AES-256-GCM for payload encryption.
- Use authenticated metadata so tampering is detectable.
- Add versioned crypto envelopes for future migrations.
- Do not reuse password hashes as encryption keys.
- Support OS keychain wrapping as an optional convenience layer, not as the primary trust model.

## Agent Access Controls

- Agents never use the master password directly.
- Agents receive scoped access tokens or local session handles.
- Access is granted through short-lived leases with TTL.
- Every lease is bound to an agent identity, task name, and policy scope.
- Leases can be revoked individually or globally.
- Audit events record access without logging secret values.

## Secret Delivery Modes

- `lease`: returns a short-lived plaintext secret only when the workflow truly requires it
- `env`: writes or streams a temporary env file from a project mapping
- `exec`: runs a subprocess with injected env vars and automatic cleanup
- `proxy`: brokers outbound HTTP requests and injects headers or auth material at the edge
- `container-config`: generates container or devcontainer runtime config for proxy and CA setup

## Capability Model

## Keep From Legacy Autho

- password vault entries
- TOTP secrets and code generation
- secure notes
- encrypted file workflows
- encrypted folder workflows
- import from legacy export formats

## Add For Agents

- agent registry
- lease issuance and revocation
- scoped policies per secret and per agent
- `.autho/secrets.json` or `.autho/project.json` project mappings
- `autho env`
- `autho exec`
- `autho lease`
- `autho revoke`
- `autho audit`
- `autho proxy`
- service templates for GitHub, OpenAI, Anthropic, Vercel, AWS, npm, Docker, and generic HTTP APIs
- MCP-friendly or tool-friendly interfaces for coding agents

## Data Model

At minimum, model these entities:

- `vaults`
- `master_keys`
- `secrets`
- `secret_versions`
- `secret_bindings`
- `projects`
- `project_secret_mappings`
- `agents`
- `agent_tokens`
- `leases`
- `audit_events`
- `rotation_hooks`
- `file_artifacts`

Each secret should track:

- stable ID
- display name
- type
- labels or tags
- encrypted payload
- encrypted data key
- metadata
- created and updated timestamps
- rotation policy
- last accessed timestamp

## CLI Surface For v2

Recommended command families:

- `autho init`
- `autho doctor`
- `autho import legacy`
- `autho secrets add`
- `autho secrets list`
- `autho secrets get`
- `autho secrets rm`
- `autho otp code`
- `autho files encrypt`
- `autho files decrypt`
- `autho agents add`
- `autho agents list`
- `autho lease create`
- `autho lease revoke`
- `autho env sync`
- `autho exec -- <command>`
- `autho audit tail`
- `autho proxy serve`
- `autho daemon serve`
- `autho web`

CLI output should follow two modes:

- human-readable by default for interactive use
- structured JSON for agent tooling and automation

## API And UI Surface

The dashboard should manage:

- onboarding and vault setup
- secret CRUD
- OTP display with copy-safe interactions
- project mappings for env injection
- agent identities and scopes
- active leases
- audit log exploration
- rotation and health status
- proxy rules and service bindings

The API should avoid accepting raw master credentials over HTTP after initial unlock.

Preferred pattern:

- local daemon performs unlock and key operations
- API talks to daemon over a trusted local channel
- remote or hosted mode uses stronger auth with sessions, device approval, or service accounts

## Agent Integration Design

## Local Coding Agent Workflow

Primary path:

1. Agent checks `autho status`.
2. Agent reads project secret mapping from `.autho/project.json`.
3. Agent runs `autho exec -- <command>` for one-shot tasks.
4. Autho injects only required env vars for the task.
5. Lease expires automatically and the audit log records the session.

## Secure Non-Exposure Workflow

For APIs that support header-based auth:

1. Agent uses a fake placeholder or agent token.
2. Agent routes HTTP traffic through `autho proxy`.
3. Proxy resolves the target service and policy.
4. Proxy injects the real credential into the outbound request.
5. Agent never receives the actual API key.

This is the closest Autho analogue to the `onecli` model and should be a major differentiator.

## MCP Or Tool Bridge

Expose a narrow tool interface for:

- listing allowed secret handles
- creating a lease
- revoking a lease
- syncing env mappings
- checking audit-safe status

Do not expose arbitrary secret dump commands through MCP or tool integrations.

## Migration Strategy

## Legacy Data Migration

- Build a read-only importer for the current `conf` store.
- Detect legacy store path and collection names automatically.
- Re-encrypt imported secrets into the new envelope format.
- Preserve timestamps where possible.
- Mark imports with source metadata for traceability.

## Capability Compatibility

Ship migration in this order:

1. import passwords, notes, and OTP records
2. verify OTP parity with test vectors
3. restore file and folder crypto flows
4. add project env mappings
5. add agent leases and audit
6. add proxy mode

## Delivery Phases

## Phase 0: Discovery And Contracts

- Document the exact legacy behaviors and storage locations.
- Write fixture exports from the current implementation.
- Define the new domain model and crypto envelope schema.
- Decide the initial scope: local-first only, or local plus self-hosted dashboard.

## Phase 1: Core Platform

- Set up a Bun-first TypeScript monorepo structure.
- Add lint, format, typecheck, unit test, and integration test pipelines.
- Implement storage, migrations, crypto, and domain services.
- Implement master unlock and vault lifecycle.

## Phase 2: Legacy Parity

- Rebuild secret CRUD.
- Rebuild OTP generation and validation.
- Rebuild file and folder encryption flows.
- Rebuild import from legacy JSON and direct legacy store migration.
- Rebuild a clean interactive CLI.

## Phase 3: Agent Workflows

- Add agents, scopes, and leases.
- Add `env` and `exec`.
- Add audit logging.
- Add rotation hooks.
- Add emergency revoke-all or killswitch flow.

## Phase 4: Dashboard

- Build secret management UI.
- Build agent and policy management UI.
- Build audit and lease views.
- Add setup and migration screens.

## Phase 5: Proxy Mode

- Implement outbound HTTP proxy or sidecar.
- Add host, path, and header injection rules.
- Add service templates and validation.
- Add container or devcontainer integration helpers.

## Phase 6: Packaging And Release

- Cross-platform builds for macOS, Linux, and Windows
- standalone local installer
- upgrade path from existing Autho installs
- docs for humans and coding agents

## Testing Strategy

- Unit tests for crypto, key derivation, OTP, policy checks, and audit formatting
- Integration tests for unlock, CRUD, import, env sync, exec, lease expiry, and revoke flows
- CLI end-to-end tests that exercise realistic user flows from process boundaries instead of calling domain APIs directly
- Fixture-based migration tests from legacy Autho stores
- Proxy tests for host and path matching plus safe header injection
- Red-team style tests to verify secrets are not logged or leaked to child process output
- Cross-platform smoke tests for Windows named pipes and Unix sockets

## Risks And Mitigations

- Crypto migration risk: use versioned envelopes and fixture-driven migration tests.
- Scope creep risk: ship local vault parity before proxy mode.
- Secret leakage risk: centralize redaction and forbid plaintext logging in shared utilities.
- UX complexity risk: keep human vault flows and agent flows as separate command families.
- Windows support risk: design daemon transport and env cleanup with Windows first-class support.

## Recommended First Implementation Slice

Build the smallest useful v2 in this order:

1. Bun-first typed core, SQLite storage, modern crypto, and unlock flow
2. secret CRUD plus OTP parity
3. `autho env` and `autho exec`
4. lease and audit model
5. legacy importer
6. dashboard
7. proxy mode

This gets Autho to a materially better product quickly while still leaving room for the gateway-based "agents never see keys" model.

## Current Rewrite Slice

The current implementation pass should establish:

- a Bun-based workspace that can run, test, and bundle locally without pnpm-specific tooling
- a secure local vault foundation using envelope encryption and SQLite
- a CLI slice that covers vault setup, secret CRUD, OTP generation, legacy JSON import, file and folder encryption, env injection, env-file sync, `exec`, and audit visibility
- end-to-end tests that mimic user behavior through the CLI on disk, not only in-memory service tests

## Definition Of Done For The Rewrite

The rewrite should be considered successful when:

- all legacy secret types and encryption workflows are supported
- legacy users can migrate without manual data surgery
- local vault workflows are faster and more reliable than the current project
- coding agents can access required services through leases, env injection, or proxy mode
- audit logs and revocation exist for all agent secret access
- Autho can be run locally without external infrastructure
- the codebase is typed, tested, and structured for future iteration
