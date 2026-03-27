# Migration To Bun Autho

## Upgrading From 3.0.0 (OS Secret Store Integration)

This version adds the ability to save your master password in the native OS secret store (macOS Keychain, Linux Secret Service, Windows Credential Manager) so vault commands unlock without prompting. This is opt-in through the setup wizard.

**Upgrade steps:**

1. Update autho: `bun install -g autho@latest`
2. Run the setup wizard: `autho init`
3. Enter your master password when prompted (to verify vault ownership).
4. The wizard will ask if you want to save your password to the OS keychain — confirm with `y`.
5. Done — all future commands unlock silently.

You can re-run `autho init` anytime to change settings (add/remove keychain storage, PIN, or TOTP).

To opt out of all OS secret store usage, set `AUTHO_DISABLE_OS_SECRETS=1`.

---

## Migrating From Legacy (conf-based) Installs

This release closes the Bun migration for the supported Autho feature set. The supported migration path is deliberately simple:

- If you already have a legacy JSON backup, import it directly.
- If your old data only exists in the legacy `conf` store, export it once with a temporary external tool or a temporary checkout of the legacy implementation, then import the JSON into the Bun vault.

Direct in-product migration from the legacy `conf` store is not included in this release.

## Supported Import Format

`autho import legacy` accepts a JSON array of records shaped like this:

```json
[
  {
    "name": "github",
    "type": "password",
    "secret": "ghp_example_secret",
    "username": "octocat",
    "url": "https://github.com",
    "description": "GitHub token"
  },
  {
    "name": "my-note",
    "type": "note",
    "secret": "release checklist",
    "description": "plain note"
  },
  {
    "name": "my-otp",
    "type": "otp",
    "secret": "JBSWY3DPEHPK3PXP",
    "username": "otp-user",
    "digits": 6,
    "algorithm": "SHA1",
    "description": "TOTP seed"
  }
]
```

## Recommended Migration Steps

1. Install autho: `bun install -g autho`
2. Prepare a JSON backup in the format above.
3. Initialize a new Bun vault.
4. Import the JSON backup.
5. Verify secrets, OTPs, and file workflows.
6. Update automation to use the Bun CLI, daemon, and env injection flows.
7. Retire the old install after validation.

Example:

```bash
autho init --vault ./.autho/vault.db --password "correct horse battery staple"
autho import legacy --vault ./.autho/vault.db --password "correct horse battery staple" --file ./legacy-backup.json --json
autho secrets list --vault ./.autho/vault.db --password "correct horse battery staple" --json
```

Or from a local checkout:

```bash
bun run autho -- init --vault ./.autho/vault.db --password "correct horse battery staple"
bun run autho -- import legacy --vault ./.autho/vault.db --password "correct horse battery staple" --file ./legacy-backup.json --json
bun run autho -- secrets list --vault ./.autho/vault.db --password "correct horse battery staple" --json
```

## If You Only Have The Old `conf` Store

That path is intentionally manual for this release because it is uncommon and highly environment-specific.

Recommended approach:

1. Use an isolated temporary environment with the old Autho code and dependencies.
2. Read the legacy `conf` store with the same collection name, data folder, and master credentials that were used originally.
3. Emit a JSON file in the supported import format.
4. Import that JSON into the Bun vault.

A one-off exporter is reasonable if needed, but it should stay outside the main Bun release path. That keeps the release simpler and safer while still leaving a workable migration path for older installs.

## Validation Checklist

After import, verify:

- `autho secrets list --password "..." --json`
- `autho secrets get --password "..." --ref <name> --json`
- `autho otp code --password "..." --ref <name> --json`
- `autho file encrypt --password "..." --input ./sample.txt`
- `autho files encrypt --password "..." --input ./folder`

## Operational Notes

- Imports are re-encrypted into the new SQLite plus envelope-encryption format.
- The old master password hash is not reused as the new vault encryption key.
- Runtime state defaults to `~/.autho`; use `AUTHO_HOME` to isolate test or migration runs from your normal local vault.
- Local daemon auth now uses `Bun.secrets` when the OS secret store is available.
- If you are uncertain about the integrity of older data, import first, validate, then rotate the most sensitive credentials.
