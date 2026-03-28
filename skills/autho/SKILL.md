---
name: autho
description: Use autho, a local-first secret manager for coding agents and humans. Trigger this skill whenever the user or agent needs to store, retrieve, or inject secrets (API keys, tokens, passwords, OTPs), encrypt/decrypt files, create short-lived secret leases, or run commands with injected environment variables. Also trigger when you see references to "autho", "AUTHO_HOME", "AUTHO_MASTER_PASSWORD", vault initialization, secret management, OTP generation, or env injection for agent workflows. If code needs an API key or secret at runtime, this skill shows you how to get it safely.
---

# Autho — Local-First Secret Manager

Autho is an npm package (`autho`) that provides encrypted secret storage, OTP generation, file encryption, and environment injection — all local-first, built on Bun.

Agents use autho to securely store and retrieve secrets without hardcoding them, inject secrets into commands via environment variables, and create short-lived leases for least-privilege access.

## Setup

Check if autho is installed, and install if not:

```bash
npm list -g autho || npm install -g autho@latest
```

Autho requires **Bun >= 1.3.10**. Verify with `bun --version`.

### Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `AUTHO_HOME` | Vault and state directory | `~/.autho` |
| `AUTHO_MASTER_PASSWORD` | Master password for non-interactive use | _(prompt)_ |
| `AUTHO_DISABLE_OS_SECRETS` | Set to `1` to disable OS keychain integration | _(unset)_ |
| `AUTHO_PIN` | PIN for non-interactive use (if PIN is set) | _(prompt)_ |
| `AUTHO_TOTP_CODE` | TOTP code for non-interactive use (if TOTP is enabled) | _(prompt)_ |

For agent workflows, set `AUTHO_MASTER_PASSWORD` so commands run non-interactively. For isolated test/CI environments, set `AUTHO_HOME` to a temp directory to avoid touching the user's real vault.

### Initialize a Vault

```bash
autho init --password "$AUTHO_MASTER_PASSWORD"
```

When run interactively (TTY), the init command launches a setup wizard that walks through each security option as a yes/no question:

1. **OS Keychain** — save master password to the native OS secret store (macOS Keychain, Windows Credential Manager, or Linux Secret Service). After saving, all commands unlock without prompting.
2. **PIN** — set a quick-unlock PIN stored in the OS keychain (local machine gate only, no cryptographic protection).
3. **TOTP** — enable authenticator app verification for vault unlock.

Run `autho init` again anytime to reconfigure these settings. For non-interactive/agent use, skip the wizard by passing `--json`.

### Authentication Resolution Order

When a command needs the master password, autho checks in this order:
1. `--password` flag
2. `AUTHO_MASTER_PASSWORD` env var
3. OS keychain (if password was saved via `autho init`)
4. Interactive prompt (TTY only)

If the password is saved in the OS keychain, agents and humans can run commands without any password flag or env var.

### Check Vault Status

```bash
autho status --password "$AUTHO_MASTER_PASSWORD" --json
```

The `--json` flag is important — always use it when parsing output programmatically. It returns structured JSON instead of human-readable text.

## Core Operations

### Secrets CRUD

**Add a password secret:**
```bash
autho secrets add --password "$PW" --name github --type password --value "$TOKEN" --username octocat --url https://github.com
```

**Add a note:**
```bash
autho secrets add --password "$PW" --name deploy-notes --type note --value "production deploy key"
```

**Add an OTP secret:**
```bash
autho secrets add --password "$PW" --name aws-otp --type otp --value "$TOTP_SEED" --username myuser
```

**Retrieve a secret:**
```bash
autho secrets get --password "$PW" --ref github --json
```

Returns: `{ "name", "type", "value", "username", "metadata", ... }`

**List all secrets:**
```bash
autho secrets list --password "$PW" --json
```

### OTP Code Generation

Generate a TOTP code for a stored OTP secret:

```bash
autho otp code --password "$PW" --ref aws-otp --json
```

Returns: `{ "code": "123456", "expiresAt": "...", "secret": "aws-otp" }`

### File Encryption / Decryption

**Encrypt a file** (produces `<file>.autho`):
```bash
autho file encrypt --password "$PW" --input ./credentials.json
```

**Decrypt a file** (requires `--force` to overwrite existing output):
```bash
autho file decrypt --password "$PW" --input ./credentials.json.autho --force
```

### Folder Encryption / Decryption

**Encrypt a folder** (produces `<folder>.autho-folder`):
```bash
autho files encrypt --password "$PW" --input ./secrets-dir
```

**Decrypt a folder:**
```bash
autho files decrypt --password "$PW" --input ./secrets-dir.autho-folder --force
```

Note: the input for folder decrypt is the `.autho-folder` path, not the original folder.

## Environment Injection

This is the most useful pattern for agents — map vault secrets to environment variables and inject them into commands.

### Step 1: Create a Project Mapping

```bash
autho project init --map GITHUB_TOKEN=github --map OPENAI_API_KEY=openai --force
```

This creates a `project.json` in `$AUTHO_HOME` that maps env var names to secret names.

### Step 2: Render Environment Variables

```bash
autho env render --password "$PW" --project-file "$AUTHO_HOME/project.json" --json
```

Returns: `{ "GITHUB_TOKEN": "ghp_...", "OPENAI_API_KEY": "sk-..." }`

### Step 3: Execute a Command with Injected Env

```bash
autho exec --password "$PW" --project-file "$AUTHO_HOME/project.json" -- node build.js
```

The child process receives the mapped secrets as environment variables without them appearing in shell history or process listings.

## Short-Lived Leases

For least-privilege agent access, create leases that auto-expire:

**Create a lease** (TTL in seconds):
```bash
autho lease create --password "$PW" --secret github --secret openai --ttl 300 --json
```

Returns: `{ "id": "...", "expiresAt": "...", "secretRefs": [...] }`

**Revoke a lease early:**
```bash
autho lease revoke --password "$PW" --lease "$LEASE_ID" --json
```

## Legacy Import

Import secrets from a JSON backup (legacy Autho or manual export):

```bash
autho import legacy --password "$PW" --file ./backup.json --json
```

Expected JSON format:
```json
[
  { "name": "github", "type": "password", "secret": "ghp_...", "username": "octocat" },
  { "name": "my-otp", "type": "otp", "secret": "JBSWY3DPEHPK3PXP", "digits": 6, "algorithm": "SHA1" },
  { "name": "note1", "type": "note", "secret": "some text" }
]
```

## Agent Workflow Recipes

### Recipe: One-shot command (keychain unlocked)

If the user has saved their password to the OS keychain via `autho init`, no env var or flag is needed:

```bash
autho exec --project-file .autho/project.json -- npm run deploy
```

### Recipe: One-shot command (env var fallback)

For headless CI or Docker where the OS keychain is unavailable:

```bash
export AUTHO_MASTER_PASSWORD="..."
autho exec --project-file .autho/project.json -- npm run deploy
```

### Recipe: Lease-scoped agent task

```bash
LEASE=$(autho lease create --secret github --secret openai --ttl 300 --json | jq -r .id)
autho exec --project-file .autho/project.json -- node agent-task.js
autho lease revoke --lease "$LEASE"
```

### Recipe: Check vault health before proceeding

```bash
STATUS=$(autho status --json 2>&1) || true
if echo "$STATUS" | jq -e '.initialized' > /dev/null 2>&1; then
  echo "Vault ready"
else
  autho init --password "$AUTHO_MASTER_PASSWORD"
fi
```

## OS Secret Store Commands

Store, retrieve, and delete arbitrary named secrets directly in the OS keychain:

```bash
autho os-secrets set --name my-token --value ghp_xxx
autho os-secrets get --name my-token --json
autho os-secrets delete --name my-token
```

These are separate from the vault — useful for storing tokens, API keys, or other values that agents need outside the vault workflow.

## Security Notes

- Secrets are encrypted at rest with AES-256-GCM envelope encryption
- Master password derives a key via scrypt (N=2^17, OWASP minimum)
- Master password storage in OS keychain is opt-in via the setup wizard
- PIN is a local machine gate only — stored as scrypt hash in OS keychain, does not encrypt vault data
- TOTP adds authenticator app verification to the unlock flow
- Daemon tokens use timing-safe comparison
- File decrypt requires `--force` to prevent accidental overwrites
- Folder decrypt validates against path traversal
- Prefer leases over long-lived access — revoke when done
- Never log or echo secret values; use `exec` to inject them into processes
- Set `AUTHO_DISABLE_OS_SECRETS=1` to disable all OS keychain integration
