# Manual Testing Guide — PIN, TOTP, and Recovery File

This guide walks through manual verification of the three new security features:
**PIN**, **TOTP vault unlock**, and **Recovery File**.

## Setup

```bash
bun install
export AUTHO_HOME=/tmp/autho-manual-test
rm -rf $AUTHO_HOME

# Init the vault (saves master password to OS keychain automatically)
bun run autho -- init --password "correct horse battery staple"
```

Expected:
```
Vault initialized at <path>
Master password saved to OS secret store. You won't be prompted again on this machine.
```

Add a test secret:

```bash
bun run autho -- secrets add --password "correct horse battery staple" --name test-secret --type note --value "hello world"
```

---

## 1. PIN

### Set PIN

```bash
# Run init again — triggers the reconfiguration wizard
bun run autho -- init --password "correct horse battery staple"
```

At the wizard prompt:
- Choose `P` to set a PIN
- Enter `1234` twice to confirm
- Choose `S` to finish

### Verify PIN protects the vault

PIN can be provided three ways (checked in this order): `AUTHO_PIN` env var → `--pin` flag → interactive prompt.

```bash
# Via interactive prompt (TTY)
bun run autho -- secrets list --password "correct horse battery staple"
# ↳ Should prompt: "PIN: ****" — enter 1234 → list appears

# Via --pin flag
bun run autho -- secrets list --password "correct horse battery staple" --pin 1234
# ↳ Should list secrets without prompting

# Via env var
AUTHO_PIN=1234 bun run autho -- secrets list --password "correct horse battery staple"
# ↳ Should list secrets without prompting

# Wrong PIN → fails
bun run autho -- secrets list --password "correct horse battery staple" --pin 0000
# ↳ Should exit 1 with: Wrong PIN

# Missing PIN (non-TTY, no flag, no env var) → fails
echo "" | bun run autho -- secrets list --password "correct horse battery staple"
# ↳ Should exit 1 with: PIN is set on this vault
```

### Remove PIN

```bash
bun run autho -- init --password "correct horse battery staple" --pin 1234
# ↳ PIN prompt, then wizard shows PIN as SET → choose P to toggle → enter 1234 → PIN removed

# Verify vault opens without PIN
bun run autho -- secrets list --password "correct horse battery staple"
# ↳ Should list secrets without any PIN prompt
```

---

## 2. TOTP Vault Unlock

### Enable TOTP

```bash
bun run autho -- init --password "correct horse battery staple"
```

At the wizard prompt:
- Choose `T` to enable TOTP
- Copy the **TOTP Secret** shown and add it to an authenticator app (Google Authenticator, 1Password, etc.)
- Or scan the `otpauth://` URI
- Enter the 6-digit code shown by your app to confirm
- Choose `S` to finish

### Verify TOTP protects the vault

```bash
# With correct TOTP code
bun run autho -- secrets list --password "correct horse battery staple"
# ↳ Prompts: "Authenticator code: ______" → enter code → list appears

# Non-interactive with --totp flag (use fresh code from app)
bun run autho -- secrets list --password "correct horse battery staple" --totp 123456
# ↳ Succeeds if code is valid

# No TOTP code provided
bun run autho -- secrets list --password "correct horse battery staple" --json
# ↳ Should fail: "TOTP is enabled — provide a 6-digit code"

# Wrong TOTP code
bun run autho -- secrets list --password "correct horse battery staple" --totp 000000
# ↳ Should fail: "Invalid or missing TOTP code"
```

### Remove TOTP

```bash
bun run autho -- init --password "correct horse battery staple"
# ↳ PIN prompt (if set), then TOTP prompt → enter current code
# At wizard: choose T → enter current TOTP code → TOTP disabled

# Verify vault opens without TOTP
bun run autho -- secrets list --password "correct horse battery staple"
# ↳ Should list secrets without any TOTP prompt
```

### Portability: copy vault to another machine

TOTP travels with the vault `.db` file. On another machine:

```bash
# Copy vault.db and run any command
bun run autho -- secrets list --vault /path/to/copied/vault.db --password "..." --totp <code>
# ↳ Works — TOTP secret is encrypted inside the vault
```

PIN does NOT travel — each machine configures its own PIN independently via `autho init`.

---

## 3. Recovery File

### Generate

```bash
bun run autho -- recovery generate --password "correct horse battery staple" --output ~/vault.recovery
```

Expected output:
```
Recovery file written to ~/vault.recovery
WARNING: Anyone with this file can open your vault. Store it offline.
```

Inspect the file:

```bash
cat ~/vault.recovery
```

Expected format:
```
================================================================================
AUTHO VAULT RECOVERY FILE
================================================================================
Generated : 2026-03-20T12:00:00.000Z
Vault     : /tmp/autho-manual-test/vault.db

WARNING: ...

RECOVERY TOKEN:
<hex-token-split-into-groups>

To use: autho unlock --recovery-file <path-to-this-file>
================================================================================
```

### Use recovery file (emergency unlock)

```bash
# Bypasses password, PIN, and TOTP entirely
bun run autho -- unlock --recovery-file ~/vault.recovery
```

Expected:
```json
{ "unlocked": true, "vaultPath": "..." }
```

### Revoke

```bash
bun run autho -- recovery revoke --password "correct horse battery staple" --json
```

Expected:
```json
{ "revoked": true }
```

### Verify revoked file no longer works

```bash
bun run autho -- unlock --recovery-file ~/vault.recovery
# ↳ Should fail with exit 1
```

### Generate a new recovery file after revoke

```bash
bun run autho -- recovery generate --password "correct horse battery staple" --output ~/vault-new.recovery
# ↳ Fresh token, old file is dead
```

---

## 4. All Three Factors Together

```bash
export AUTHO_HOME=/tmp/autho-full-test
rm -rf $AUTHO_HOME

# Init
bun run autho -- init --password "correct horse battery staple"

# Set PIN and TOTP via wizard
bun run autho -- init --password "correct horse battery staple"
# ↳ Toggle P (set PIN = 1234), Toggle T (add to authenticator app), Done

# Generate recovery file (must pass TOTP now)
bun run autho -- recovery generate \
  --password "correct horse battery staple" \
  --totp <current-code> \
  --output ~/vault-full.recovery

# Normal daily unlock: password (OS keychain) → PIN → TOTP → vault opens
bun run autho -- secrets list
# ↳ Prompts PIN, then TOTP code → list appears

# Emergency: recovery file bypasses everything
bun run autho -- unlock --recovery-file ~/vault-full.recovery --json
# ↳ { "unlocked": true }
```

### Full unlock order (all factors set)

1. Master password — loaded from OS keychain (or `--password`, `AUTHO_MASTER_PASSWORD`, or prompted)
2. PIN — if set on this machine: `PIN: ****` prompt (or `--pin` flag)
3. TOTP — if enabled in vault: `Authenticator code: ______` prompt (or `--totp` flag)
4. Vault opens

Recovery file bypasses all three steps.

---

## 5. Audit Trail

```bash
bun run autho -- audit list --password "correct horse battery staple" --json | jq '.[].eventType'
```

Expect to see events like:
- `auth.totp.enabled`
- `auth.totp.removed`
- `auth.recovery.generated`
- `auth.recovery.revoked`

PIN events are intentionally **not** in the audit log — PIN is local-only and does not touch the vault file.

---

## 6. CI / Agent Env Vars

All three factors have env var support for headless automation:

```bash
# Resolution order for each factor:
# Password:  AUTHO_MASTER_PASSWORD > OS keychain > --password > interactive prompt
# PIN:       AUTHO_PIN > --pin > interactive prompt
# TOTP:      AUTHO_TOTP_CODE > --totp > interactive prompt

AUTHO_MASTER_PASSWORD="correct horse battery staple" \
  AUTHO_PIN="1234" \
  AUTHO_TOTP_CODE="$(your-totp-generator)" \
  bun run autho -- secrets list --vault /path/to/vault.db
```

---

## 7. Opt Out

```bash
# Disable OS secret store (no keychain, no PIN)
AUTHO_DISABLE_OS_SECRETS=1 bun run autho -- secrets list \
  --password "correct horse battery staple" \
  --totp <current-code>
# ↳ PIN check is skipped (OS secrets disabled), TOTP still required
```
