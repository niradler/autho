#!/usr/bin/env bun

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { createInterface } from "node:readline/promises";
import { basename, isAbsolute, resolve } from "node:path";
import { CLEAR_COMMAND, runDetachedClear } from "./clipboard.ts";
import { newPrfSalt, runPasskeyCeremony } from "./passkey.ts";
import pkg from "../package.json";
import { confirm, readLine, readPasswordMasked } from "./password.ts";

import {
  daemonExec,
  daemonLock,
  daemonRenderEnv,
  daemonStatus,
  daemonStop,
  daemonUnlock,
  defaultDaemonStatePath,
  startDaemonServer,
} from "../../../packages/core/src/daemon.ts";
import {
  VaultService,
  type SealChange,
  type UnlockCredentials,
  type AuthoConfig,
  PREFERENCES,
  authoConfigDir,
  configFilePath,
  defaultProjectFilePath,
  defaultVaultPath,
  formatPreference,
  loadConfig,
  numberPreference,
  parsePreference,
  preferenceSpec,
  resolvePreference,
  saveConfig,
  setPreference,
  resolveMappings,
  writeProjectConfig,
} from "../../../packages/core/src/index.ts";
import {
  deleteOsSecret,
  deleteVaultPassword,
  getOsSecret,
  hasPinSet,
  closeSessionAndRecordSeal,
  loadSealRecord,
  loadVaultPassword,
  saveSealRecord,
  osSecretsDisabled,
  setOsSecret,
  storePinHash,
  storeVaultPassword,
  verifyPin,
  deletePin,
} from "../../../packages/core/src/os-secrets.ts";
import { startWebServer } from "../../web/src/server.ts";

type ParsedArgs = {
  options: Record<string, boolean | string | string[]>;
  passthrough: string[];
  positionals: string[];
};

/** First positional: the command group. */
enum Scope {
  Audit = "audit",
  Config = "config",
  Daemon = "daemon",
  Env = "env",
  Exec = "exec",
  File = "file",
  Files = "files",
  Help = "help",
  HelpFlag = "--help",
  Import = "import",
  Init = "init",
  Lease = "lease",
  Link = "link",
  OsSecrets = "os-secrets",
  Otp = "otp",
  Passkey = "passkey",
  Password = "password",
  Project = "project",
  Prompt = "prompt",
  Recovery = "recovery",
  Secrets = "secrets",
  Status = "status",
  Unlink = "unlink",
  Unlock = "unlock",
  Vault = "vault",
  Version = "version",
  Web = "web",
}

/** Second (and third) positional: what to do within a scope. */
enum Action {
  Add = "add",
  Change = "change",
  Code = "code",
  Create = "create",
  Decrypt = "decrypt",
  Delete = "delete",
  Edit = "edit",
  Encrypt = "encrypt",
  Env = "env",
  Exec = "exec",
  Exit = "exit",
  Generate = "generate",
  Get = "get",
  Init = "init",
  Legacy = "legacy",
  List = "list",
  Lock = "lock",
  Otp = "otp",
  Path = "path",
  Read = "read",
  Remove = "remove",
  Reseal = "reseal",
  Render = "render",
  Revoke = "revoke",
  Rm = "rm",
  Serve = "serve",
  Set = "set",
  Show = "show",
  Status = "status",
  Stop = "stop",
  Sync = "sync",
  Unlock = "unlock",
  Unset = "unset",
  Verify = "verify",
}

function parseArgs(argv: string[]): ParsedArgs {
  const dashDashIndex = argv.indexOf("--");
  const main = dashDashIndex === -1 ? argv : argv.slice(0, dashDashIndex);
  const passthrough = dashDashIndex === -1 ? [] : argv.slice(dashDashIndex + 1);
  const positionals: string[] = [];
  const options: Record<string, boolean | string | string[]> = {};

  for (let index = 0; index < main.length; index += 1) {
    const token = main[index];
    if (!token.startsWith("--")) {
      positionals.push(token);
      continue;
    }

    const key = token.slice(2);
    const next = main[index + 1];
    if (!next || next.startsWith("--")) {
      options[key] = true;
      continue;
    }

    const current = options[key];
    if (current === undefined) {
      options[key] = next;
    } else if (Array.isArray(current)) {
      current.push(next);
    } else {
      options[key] = [current as string, next];
    }
    index += 1;
  }

  return { options, passthrough, positionals };
}

function getString(args: ParsedArgs, key: string): string | undefined {
  const value = args.options[key];
  return typeof value === "string" ? value : undefined;
}

function getStrings(args: ParsedArgs, key: string): string[] {
  const value = args.options[key];
  if (Array.isArray(value)) {
    return value.filter((entry): entry is string => typeof entry === "string");
  }
  if (typeof value === "string") {
    return [value];
  }

  return [];
}

function getBoolean(args: ParsedArgs, key: string): boolean {
  return args.options[key] === true;
}

function required(value: string | undefined, label: string): string {
  if (!value) {
    throw new Error(`Missing required option: ${label}`);
  }

  return value;
}

function requirePositiveInt(value: string, label: string): number {
  const num = Number(value);
  if (!Number.isFinite(num) || num <= 0 || Math.floor(num) !== num) {
    throw new Error(`${label} must be a positive integer`);
  }
  return num;
}

/** `--ttl`, else the defaultLeaseTtl setting; 0 there means --ttl stays required. */
function leaseTtl(args: ParsedArgs): number {
  const ttl = getString(args, "ttl");
  if (ttl) return requirePositiveInt(ttl, "--ttl");
  const fallback = numberPreference("defaultLeaseTtl");
  if (fallback > 0) return fallback;
  return requirePositiveInt(required(ttl, "--ttl"), "--ttl");
}

function output(value: unknown, jsonMode = false): void {
  if (jsonMode) {
    console.log(JSON.stringify(value, null, 2));
    return;
  }

  if (Array.isArray(value)) {
    console.table(value);
    return;
  }

  if (typeof value === "object" && value !== null) {
    console.log(JSON.stringify(value, null, 2));
    return;
  }

  console.log(value);
}

function printSealChanges(changes: SealChange[], diffTrusted: boolean): void {
  if (!diffTrusted && changes.length > 0) {
    console.log("The stored row signatures were edited too, so the list below may be incomplete.");
  }
  for (const change of changes) {
    console.log(`  ${change.change.padEnd(8)} ${change.table} ${change.rowId}`);
  }
}

function absolutePath(path: string): string {
  return resolve(path);
}

function buildSecretMetadata(args: ParsedArgs): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries({
      algorithm: getString(args, "algorithm"),
      description: getString(args, "description"),
      digits: getString(args, "digits") ? Number(getString(args, "digits")) : undefined,
      url: getString(args, "url"),
    }).filter(([, value]) => value !== undefined),
  );
}

type PromptAdapter = {
  ask(prompt: string): Promise<string>;
  close(): void;
};

async function readBufferedStdin(): Promise<string[]> {
  process.stdin.setEncoding("utf8");
  let input = "";
  for await (const chunk of process.stdin) {
    input += chunk;
  }
  return input.split(/\r?\n/);
}

async function createPromptAdapter(): Promise<PromptAdapter> {
  if (process.stdin.isTTY) {
    const rl = createInterface({
      input: process.stdin,
      output: process.stdout,
    });
    return {
      ask: async (prompt: string) => (await rl.question(prompt)).trim(),
      close: () => rl.close(),
    };
  }

  const answers = await readBufferedStdin();
  let index = 0;

  return {
    ask: async (prompt: string) => {
      process.stdout.write(prompt);
      const value = answers[index] ?? "";
      index += 1;
      return value.trim();
    },
    close: () => undefined,
  };
}

async function askPassword(prompt: PromptAdapter, initial?: string): Promise<string> {
  if (initial) {
    return initial;
  }

  // Use masked input when running in a TTY
  if (process.stdin.isTTY) {
    return readPasswordMasked("Master password: ");
  }

  return prompt.ask("Master password: ");
}

async function runPromptMode(vaultPath: string, initialPassword?: string): Promise<void> {
  const prompt = await createPromptAdapter();

  try {
    const password = await askPassword(prompt, initialPassword);
    const session = VaultService.unlock(vaultPath, { password, sealRecord: await loadSealRecord(vaultPath) });
    try {
      const action = (await prompt.ask("Action [create/read/list/delete/otp/exit]: ")).toLowerCase();

      if (action === Action.Exit) {
        return;
      }

      if (action === Action.List) {
        output(session.listSecrets());
        return;
      }

      if (action === Action.Read) {
        const ref = await prompt.ask("Secret ref: ");
        output(session.getSecret(ref));
        return;
      }

      if (action === Action.Delete) {
        const ref = await prompt.ask("Secret ref: ");
        output(session.removeSecret(ref));
        return;
      }

      if (action === Action.Otp) {
        const ref = await prompt.ask("OTP ref: ");
        output(session.generateOtp(ref));
        return;
      }

      if (action === Action.Create) {
        const name = await prompt.ask("Name: ");
        const type = (await prompt.ask("Type [password/note/otp]: ")).toLowerCase();
        const value = await prompt.ask("Value: ");
        const username = type !== "note" ? await prompt.ask("Username (optional): ") : "";
        const url = type === "password" ? await prompt.ask("URL (optional): ") : "";
        const description = await prompt.ask("Description (optional): ");
        const digits = type === "otp" ? await prompt.ask("Digits [6]: ") : "";
        const algorithm = type === "otp" ? await prompt.ask("Algorithm [SHA1]: ") : "";

        output(
          session.addSecret({
            metadata: Object.fromEntries(
              Object.entries({
                algorithm: algorithm || undefined,
                description: description || undefined,
                digits: digits ? Number(digits) : undefined,
                url: url || undefined,
              }).filter(([, entry]) => entry !== undefined),
            ),
            name,
            type,
            username: username || undefined,
            value,
          }),
        );
        return;
      }

      throw new Error(`Unknown prompt action: ${action}`);
    } finally {
      await closeSessionAndRecordSeal(vaultPath, session);
    }
  } finally {
    prompt.close();
  }
}
/** `--passkey` unlocks with a registered passkey or security key instead of the password. */
function wantsPasskey(args: ParsedArgs): boolean {
  return args.options.passkey !== undefined;
}

function printCeremonyUrl(url: string, opened: boolean): void {
  // stderr keeps --json output on stdout clean.
  console.error(opened
    ? `Opened your browser to use a passkey. If nothing appeared, open:\n  ${url}`
    : `Open this link in a browser on this machine to use a passkey:\n  ${url}`);
}

async function passkeyCredentials(vaultPath: string): Promise<UnlockCredentials> {
  const passkeys = VaultService.listPasskeys(vaultPath);
  if (passkeys.length === 0) {
    throw new Error("No passkeys are registered for this vault — add one with `autho passkey add`");
  }
  const result = await runPasskeyCeremony(
    { mode: "authenticate", credentials: passkeys.map(({ credentialId, prfSalt, transports }) => ({ credentialId, prfSalt, transports })) },
    { onUrl: printCeremonyUrl },
  );
  return { password: "", passkey: { credentialId: result.credentialId, prfOutput: result.prfOutput } };
}

async function resolveUnlockCredentials(
  vaultPath: string,
  args: ParsedArgs,
  existingPassword?: string,
): Promise<UnlockCredentials> {
  const sealRecord = await loadSealRecord(vaultPath);

  // A passkey replaces password, PIN and TOTP: the authenticator already
  // required user verification (biometric or PIN) to release its PRF value.
  if (wantsPasskey(args)) {
    return { ...(await passkeyCredentials(vaultPath)), sealRecord };
  }

  // Password: --password > AUTHO_MASTER_PASSWORD > OS keychain > interactive prompt
  let password = existingPassword ?? getString(args, "password") ?? process.env.AUTHO_MASTER_PASSWORD;
  if (!password) {
    password = (await loadVaultPassword(vaultPath)) ?? undefined;
  }
  if (!password && process.stdin.isTTY) {
    password = await readPasswordMasked("Master password: ");
  }

  const creds: UnlockCredentials = { password: required(password, "--password"), sealRecord };

  // PIN check (if set on this machine)
  // Resolution order: AUTHO_PIN env var > --pin flag > interactive prompt
  if (await hasPinSet(vaultPath)) {
    const pin = process.env.AUTHO_PIN
      ?? getString(args, "pin")
      ?? (process.stdin.isTTY ? await readPasswordMasked("PIN: ") : undefined);
    if (!pin) throw new Error("PIN is set on this vault — provide it with AUTHO_PIN, --pin, or interactively");
    const ok = await verifyPin(vaultPath, pin);
    if (!ok) throw new Error("Wrong PIN");
  }

  // TOTP check (if enabled in vault)
  // Resolution order: AUTHO_TOTP_CODE env var > --totp flag > interactive prompt
  const authConfig = VaultService.getAuthConfig(vaultPath);
  if (authConfig?.totp) {
    const totp = process.env.AUTHO_TOTP_CODE
      ?? getString(args, "totp")
      ?? (process.stdin.isTTY ? await readPasswordMasked("Authenticator code: ") : undefined);
    if (!totp) throw new Error("TOTP is enabled — provide a 6-digit code with AUTHO_TOTP_CODE, --totp, or interactively");
    creds.totp = totp;
  }

  return creds;
}

function osKeychainName(): string {
  const p = process.platform;
  if (p === "darwin") return "macOS Keychain";
  if (p === "win32") return "Windows Credential Manager";
  return "Secret Service (libsecret)";
}

async function runInitWizard(vaultPath: string, password: string, existingCreds?: UnlockCredentials): Promise<void> {
  const creds: UnlockCredentials = existingCreds ?? { password };

  console.log("");

  // ── OS Keychain ──────────────────────────────────────────────────
  if (!osSecretsDisabled()) {
    const passwordStored = (await loadVaultPassword(vaultPath)) !== null;

    if (passwordStored) {
      console.log(`\x1b[32m✓\x1b[0m Master password is saved in ${osKeychainName()}.`);
      if (await confirm("  Remove it?", false)) {
        const deleted = await deleteVaultPassword(vaultPath);
        console.log(deleted ? "  Removed." : "  Could not remove.");
      }
    } else {
      console.log(`\x1b[33m?\x1b[0m Save master password to ${osKeychainName()}?`);
      console.log("  This lets all vault commands unlock without prompting on this machine.");
      if (await confirm("  Save to keychain?")) {
        const stored = await storeVaultPassword(vaultPath, password);
        console.log(stored ? "  \x1b[32m✓\x1b[0m Saved." : "  Could not save — OS secret store may be unavailable.");
      } else {
        console.log("  Skipped.");
      }
    }
    console.log("");
  }

  // ── PIN ──────────────────────────────────────────────────────────
  if (!osSecretsDisabled()) {
    const pinSet = await hasPinSet(vaultPath);

    if (pinSet) {
      console.log("\x1b[32m✓\x1b[0m PIN is set on this machine.");
      if (await confirm("  Remove PIN?", false)) {
        const pin = await readPasswordMasked("  Enter current PIN: ");
        const ok = await verifyPin(vaultPath, pin);
        if (ok) {
          await deletePin(vaultPath);
          console.log("  Removed.");
        } else {
          console.log("  Wrong PIN, not removed.");
        }
      }
    } else {
      if (await confirm("Set up a PIN for quick unlock on this machine?", false)) {
        const newPin = await readPasswordMasked("  New PIN: ");
        if (!newPin) {
          console.log("  PIN cannot be empty, skipped.");
        } else {
          const confirmPin = await readPasswordMasked("  Confirm PIN: ");
          if (newPin !== confirmPin) {
            console.log("  PINs do not match, skipped.");
          } else {
            await storePinHash(vaultPath, newPin);
            console.log("  \x1b[32m✓\x1b[0m PIN set.");
          }
        }
      }
    }
    console.log("");
  }

  // ── TOTP ─────────────────────────────────────────────────────────
  const authConfig = VaultService.getAuthConfig(vaultPath);
  const totpEnabled = authConfig?.totp !== undefined;

  if (totpEnabled) {
    console.log("\x1b[32m✓\x1b[0m TOTP is enabled (authenticator app required to unlock).");
    if (await confirm("  Disable TOTP?", false)) {
      const code = await readPasswordMasked("  Enter current TOTP code: ");
      try {
        VaultService.removeTotp(vaultPath, { ...creds, totp: code });
        console.log("  Disabled.");
      } catch (e) {
        console.log(`  Error: ${e instanceof Error ? e.message : String(e)}`);
      }
    }
  } else {
    if (await confirm("Enable TOTP (authenticator app verification)?", false)) {
      const { secret, uri } = VaultService.setupTotp(vaultPath);
      console.log("");
      console.log(`  Secret: ${secret}`);
      console.log(`  URI:    ${uri}`);
      console.log("");
      console.log("  Add this to your authenticator app, then enter the 6-digit code.");
      const code = await readPasswordMasked("  Code: ");
      try {
        VaultService.enableTotp(vaultPath, creds, secret, code);
        console.log("  \x1b[32m✓\x1b[0m TOTP enabled.");
      } catch (e) {
        console.log(`  Error: ${e instanceof Error ? e.message : String(e)}`);
      }
    }
  }

  console.log("");
  console.log("Setup complete. Run \x1b[1mautho init\x1b[0m anytime to change these settings.");
}

async function runWebServer(vaultPath: string, args: ParsedArgs): Promise<void> {
  // In-process, so it works from the published bundle and not just the repo.
  await startWebServer({
    host: getString(args, "host"),
    port: Number(getString(args, "port") ?? numberPreference("webPort")),
    vaultPath: absolutePath(vaultPath),
  });
}

function help(): string {
  return [
    "Autho – Local-first secret manager for humans and coding agents",
    "",
    "Usage:",
    "  autho                  Open interactive TUI (terminal UI)",
    "  autho <command>        Run a CLI command (see below)",
    "",
    "Commands:",
    "  prompt [--vault <path>]",
    "  init [--vault <path>]",
    "  status [--vault <path>] [--project-file <path>] [--json]",
    "  config [show]                   Show current configuration",
    "  config set <key> <value>        Set a config value",
    "  config unset <key>              Remove a config value",
    "  config path                     Print config file path",
    "  project init --map <ENV=ref> [--output <path>] [--force] [--json]",
    "  web serve [--vault <path>] [--host <value>] [--port <value>]",
    "  daemon serve [--vault <path>] [--state-file <path>] [--host <value>] [--port <value>]",
    "  daemon status [--state-file <path>] [--json]",
    "  daemon unlock [--ttl <seconds>] [--state-file <path>] [--json]",
    "  daemon lock --session <id> [--state-file <path>] [--json]",
    "  daemon stop [--state-file <path>] [--json]",
    "  daemon env render --session <id> --map <ENV=ref> [--project-file <path>] [--lease <id>] [--state-file <path>] [--json]",
    "  daemon exec --session <id> --map <ENV=ref> [--project-file <path>] [--lease <id>] [--state-file <path>] -- <cmd>",
    "  import legacy --file <path> [--skip-existing] [--vault <path>] [--json]",
    "  secrets add --name <name> --type <password|note|otp> --value <value> [--username <v>] [--url <v>] [--description <v>] [--digits <v>] [--algorithm <v>] [--vault <path>]",
    "  secrets list [--vault <path>] [--json]",
    "  secrets get --ref <name-or-id> [--links] [--vault <path>] [--json]",
    "  secrets rm --ref <name-or-id> [--with-linked] [--vault <path>] [--json]",
    "  link <primary> <secret> [--vault <path>] [--json]      Show <secret> on <primary>'s page",
    "  unlink <primary> <secret> [--vault <path>] [--json]",
    "  secrets edit --ref <name-or-id> [--new-name <v>] [--value <v>] [--username <v>] [--url <v>] [--description <v>] [--vault <path>] [--json]",
    "  otp code --ref <name-or-id> [--vault <path>] [--json]",
    "  lease create --secret <ref> [--secret <ref>] [--ttl <seconds>] [--name <v>] [--no-links] [--vault <path>] [--json]",
    "  lease show --lease <id> [--vault <path>] [--json]",
    "  lease revoke --lease <id> [--vault <path>] [--json]",
    "  vault verify [--vault <path>] [--json]",
    "  vault reseal [--accept] [--vault <path>] [--json]",
    "  env render --map <ENV=ref> [--project-file <path>] [--lease <id>] [--vault <path>] [--json]",
    "  env sync --map <ENV=ref> [--project-file <path>] [--lease <id>] [--ttl <seconds>] [--output <path>] [--force] [--vault <path>] [--json]",
    "  exec --map <ENV=ref> [--project-file <path>] [--lease <id>] [--vault <path>] -- <cmd>",
    "  file encrypt --input <path> [--output <path>] [--force] [--vault <path>] [--json]",
    "  file decrypt --input <path> [--output <path>] [--force] [--vault <path>] [--json]",
    "  files encrypt --input <path> [--output <path>] [--force] [--vault <path>] [--json]",
    "  files decrypt --input <path> [--output <path>] [--force] [--vault <path>] [--json]",
    "  audit list [--limit <number>] [--vault <path>] [--json]",
    "  recovery generate --output <path> [--vault <path>] [--json]",
    "  recovery revoke [--vault <path>] [--json]",
    "  unlock --recovery-file <path> [--vault <path>] [--json]",
    "  passkey add [--label <name>] [--vault <path>] [--json]",
    "  passkey list [--vault <path>] [--json]",
    "  passkey remove <id-or-label> [--vault <path>] [--json]",
    "  password change [--new-password <value>] [--vault <path>] [--json]",
    "  os-secrets set --name <name> [--value <value>] [--json]",
    "  os-secrets get --name <name> [--json]",
    "  os-secrets delete --name <name> [--json]",
    "",
    "Authentication:",
    "  When running interactively (TTY), you will be securely prompted for your",
    "  master password with masked input (no --password flag needed).",
    "",
    "  For automation and coding agents, use one of:",
    "    autho init                        Setup wizard — choose to save password in OS keychain, set PIN, enable TOTP",
    "    AUTHO_MASTER_PASSWORD=<value>    Environment variable (master password)",
    "    AUTHO_PIN=<value>                Environment variable (PIN, if set on this machine)",
    "    AUTHO_TOTP_CODE=<value>          Environment variable (TOTP code, if enabled)",
    "    --password <value>               CLI flag (visible in shell history - avoid!)",
    "",
    "  Passkeys and security keys (WebAuthn PRF / hmac-secret):",
    "    autho passkey add                Register one (opens a browser page on localhost)",
    "    --passkey                        Unlock any command with it instead of the password",
    "    In the TUI, press ctrl+p on the unlock screen.",
    "",
    "  Native OS secret store support (via Bun.secrets):",
    "    macOS   → Keychain Services",
    "    Linux   → libsecret / GNOME Keyring / KWallet",
    "    Windows → Windows Credential Manager",
    "",
    "  The OS secret store is checked automatically before prompting.",
    "  Set AUTHO_DISABLE_OS_SECRETS=1 to opt out.",
    "",
    "Notes:",
    "  Running `autho` with no arguments opens the interactive TUI.",
    "  Config is stored in ~/.autho/config.json (always at ~/.autho).",
    "  The vault directory can be customized via `autho init` or `autho config set vaultDir <path>`.",
    "  Config keys: vaultDir, revealSeconds, clipboardClearSeconds, idleLockSeconds, passwordLength,",
    "    passwordSymbols, mouse, defaultLeaseTtl, daemonTtlSeconds, webPort (see `autho config show`).",
    "  lease create uses the defaultLeaseTtl setting when --ttl is omitted (0 = --ttl required).",
    "  A lease on a secret also covers the secrets linked to it, read live (--no-links to opt out).",
    "  env and exec inject an OTP secret's current code, never its seed.",
    "  The vault is sealed: edits made outside autho stop env, exec and leases until `autho vault reseal`.",
    "  In the TUI, press , for Settings. `autho --version` prints the installed version.",
    "  The default vault path is ~/.autho/vault.db (override with config or AUTHO_HOME).",
    "  The default project file is <vaultDir>/project.json.",
    "  The default daemon state file is <vaultDir>/daemon.json.",
  ].join("\n");
}

async function main(): Promise<void> {
  // Internal: detached helper spawned by the TUI to clear a copied secret after exit.
  if (process.argv[2] === CLEAR_COMMAND) {
    await runDetachedClear(process.argv[3]);
    return;
  }

  const args = parseArgs(process.argv.slice(2));
  const [scope, action, subaction] = args.positionals;
  if (scope === Scope.Version || (!scope && process.argv.includes("--version"))) {
    console.log(pkg.version);
    return;
  }
  const jsonMode = getBoolean(args, "json");
  const vaultPath = getString(args, "vault") ?? defaultVaultPath();
  const statePath = absolutePath(getString(args, "state-file") ?? defaultDaemonStatePath());
  const explicitProjectFile = getString(args, "project-file");
  const fallbackProjectFile = defaultProjectFilePath();
  const projectFile = explicitProjectFile ?? (existsSync(fallbackProjectFile) ? fallbackProjectFile : undefined);
  let password = getString(args, "password") ?? process.env.AUTHO_MASTER_PASSWORD;

  // Fall back to OS secret store before prompting interactively
  if (!password) {
    password = (await loadVaultPassword(vaultPath)) ?? undefined;
  }

  // `--help` parses as a flag, which leaves scope empty.
  if (!scope && (process.argv.includes("--help") || process.argv.includes("-h"))) {
    console.log(help());
    return;
  }

  if (!scope) {
    // TUI mode when running interactively with no args
    if (process.stdin.isTTY) {
      const { runTui } = await import("./tui.tsx");
      await runTui(vaultPath);
      return;
    }
    // Non-TTY: use the text-based prompt mode
    await runPromptMode(vaultPath, password);
    return;
  }

  if (scope === Scope.Help || scope === Scope.HelpFlag) {
    console.log(help());
    return;
  }

  if (scope === Scope.Prompt) {
    await runPromptMode(vaultPath, password);
    return;
  }

  // Auto-prompt for password when running interactively and no --password/env var
  if (!password && process.stdin.isTTY && !wantsPasskey(args)) {
    const needsPassword = ([
      Scope.Secrets, Scope.Otp, Scope.Lease, Scope.Env, Scope.Exec,
      Scope.File, Scope.Files, Scope.Audit, Scope.Import, Scope.Recovery, Scope.Unlock,
      Scope.Link, Scope.Unlink, Scope.Vault,
    ] as string[]).includes(scope ?? "");
    const daemonNeedsPassword = scope === Scope.Daemon && action === Action.Unlock;
    if (needsPassword || daemonNeedsPassword) {
      password = await readPasswordMasked("Master password: ");
    }
  }

  if (scope === Scope.Init) {
    let effectiveVaultPath = vaultPath;

    // Interactive vault directory selection (first run only, TTY only)
    if (!VaultService.status(vaultPath).initialized && process.stdin.isTTY && !jsonMode) {
      const config = loadConfig();
      const currentDir = config.vaultDir ?? authoConfigDir();
      console.log(`\n\x1b[1mVault directory\x1b[0m`);
      console.log(`  Default: ${currentDir}`);
      console.log("  Tip: Use a cloud-synced folder (e.g. Google Drive) to share the vault across machines.");
      const customDir = (await readLine(`  Path (Enter to keep default): `)).trim();
      if (customDir && customDir !== currentDir) {
        const resolved = resolve(customDir).replace(/\\/g, "/");
        saveConfig({ ...config, vaultDir: resolved });
        effectiveVaultPath = resolved + "/vault.db";
        console.log(`  \x1b[32m✓\x1b[0m Vault directory set to ${resolved}`);
        console.log(`  Config saved to ${authoConfigDir()}/config.json`);
      }
      console.log("");
    }

    const existingStatus = VaultService.status(effectiveVaultPath);

    if (!existingStatus.initialized) {
      // First run: create vault
      const pw = required(password, "--password");
      output(VaultService.initialize(effectiveVaultPath, pw), jsonMode);

      // Interactive setup wizard (TTY only, not in --json mode)
      if (process.stdin.isTTY && !jsonMode) {
        await runInitWizard(effectiveVaultPath, pw);
      }
    } else {
      // Reconfigure: full security check first
      const creds = await resolveUnlockCredentials(effectiveVaultPath, args, password);
      if (process.stdin.isTTY && !jsonMode) {
        await runInitWizard(effectiveVaultPath, creds.password, creds);
      } else {
        console.log("Vault already initialized. Use interactive mode (TTY) to reconfigure.");
      }
    }
    return;
  }

  if (scope === Scope.Status) {
    output(
      VaultService.status(vaultPath, {
        password,
        projectFile,
      }),
      jsonMode,
    );
    return;
  }

  if (scope === Scope.Config) {
    const config = loadConfig();
    const configKeys = ["vaultDir", "editor", "autoLock", "autoLockTimeout", ...PREFERENCES.map((spec) => spec.key)];

    if (!action || action === Action.Show) {
      const preferences = Object.fromEntries(PREFERENCES.map((spec) => [spec.key, resolvePreference(spec.key)]));
      if (jsonMode) {
        output({ configDir: authoConfigDir(), config, preferences }, jsonMode);
      } else {
        console.log(`Config: ${configFilePath()}`);
        console.log(`Vault dir: ${config.vaultDir ?? authoConfigDir()} ${config.vaultDir ? "(custom)" : "(default)"}`);
        if (config.editor) console.log(`Editor: ${config.editor}`);
        for (const spec of PREFERENCES) {
          const { value, source } = resolvePreference(spec.key);
          const from = source === "env" ? ` (from ${spec.env})` : source === "default" ? " (default)" : "";
          console.log(`${spec.label}: ${formatPreference(spec.key, value)}${from}   [${spec.key}]`);
        }
      }
      return;
    }

    if (action === Action.Set) {
      const key = subaction;
      const value = process.argv[process.argv.indexOf("set") + 2];
      if (!key || value === undefined) {
        console.error("Usage: autho config set <key> <value>");
        console.error(`Keys: ${configKeys.join(", ")}`);
        process.exit(1);
      }
      const spec = preferenceSpec(key);
      if (spec) {
        setPreference(spec.key, parsePreference(spec.key, value));
      } else {
        const updated: AuthoConfig = { ...config };
        if (key === "autoLock") {
          updated.autoLock = value === "true";
        } else if (key === "vaultDir") {
          updated.vaultDir = isAbsolute(value) ? value : resolve(value);
        } else if (key === "editor") {
          updated.editor = value;
        } else if (key === "autoLockTimeout") {
          updated.autoLockTimeout = value;
        } else {
          console.error(`Unknown config key: ${key}`);
          console.error(`Keys: ${configKeys.join(", ")}`);
          process.exit(1);
        }
        saveConfig(updated);
      }
      console.log(`Set ${key} = ${value}`);
      return;
    }

    if (action === Action.Unset) {
      const key = subaction;
      if (!key) {
        console.error("Usage: autho config unset <key>");
        process.exit(1);
      }
      const spec = preferenceSpec(key);
      if (spec) {
        setPreference(spec.key, null);
      } else {
        const updated: AuthoConfig = { ...config };
        delete updated[key as keyof AuthoConfig];
        saveConfig(updated);
      }
      console.log(`Removed ${key}`);
      return;
    }

    if (action === Action.Path) {
      console.log(authoConfigDir() + "/config.json");
      return;
    }

    console.error(`Unknown config action: ${action}. Use: show, set, unset, path`);
    process.exit(1);
  }

  if (scope === Scope.Project && action === Action.Init) {
    output(
      writeProjectConfig({
        force: getBoolean(args, "force"),
        mappings: resolveMappings({ maps: getStrings(args, "map") }),
        outputPath: absolutePath(getString(args, "output") ?? projectFile ?? defaultProjectFilePath()),
      }),
      jsonMode,
    );
    return;
  }

  if (scope === Scope.OsSecrets && action === Action.Set) {
    const name = required(getString(args, "name"), "--name");
    const value = getString(args, "value") ?? await readPasswordMasked(`Value for "${name}": `);
    const stored = await setOsSecret(name, value);
    if (!stored) {
      throw new Error("OS secret store is unavailable on this system (try AUTHO_DISABLE_OS_SECRETS=1 to confirm, or check that a secret service daemon is running on Linux)");
    }
    output({ name, stored: true }, jsonMode);
    return;
  }

  if (scope === Scope.OsSecrets && action === Action.Get) {
    const name = required(getString(args, "name"), "--name");
    const value = await getOsSecret(name);
    if (value === null) {
      throw new Error(`Secret "${name}" not found in OS secret store`);
    }
    output({ name, value }, jsonMode);
    return;
  }

  if (scope === Scope.OsSecrets && action === Action.Delete) {
    const name = required(getString(args, "name"), "--name");
    const deleted = await deleteOsSecret(name);
    output({ deleted, name }, jsonMode);
    return;
  }

  if (scope === Scope.Web && action === Action.Serve) {
    await runWebServer(vaultPath, args);
    return;
  }

  if (scope === Scope.Daemon && action === Action.Serve) {
    await startDaemonServer({
      host: getString(args, "host") ?? "127.0.0.1",
      port: Number(getString(args, "port") ?? "0"),
      statePath,
      vaultPath: absolutePath(vaultPath),
    });
    return;
  }

  if (scope === Scope.Daemon && action === Action.Status) {
    output(await daemonStatus({ statePath }), jsonMode);
    return;
  }

  if (scope === Scope.Daemon && action === Action.Unlock) {
    // Same checks as any unlock (PIN, TOTP); the daemon itself needs the password.
    const creds = await resolveUnlockCredentials(vaultPath, args, password);
    if (creds.passkey || creds.recovery) throw new Error("daemon unlock needs the master password");
    output(
      await daemonUnlock({
        password: creds.password,
        statePath,
        totp: creds.totp,
        ttlSeconds: getString(args, "ttl") ? Number(getString(args, "ttl")) : numberPreference("daemonTtlSeconds"),
      }),
      jsonMode,
    );
    return;
  }

  if (scope === Scope.Daemon && action === Action.Lock) {
    output(
      await daemonLock({
        sessionId: required(getString(args, "session"), "--session"),
        statePath,
      }),
      jsonMode,
    );
    return;
  }

  if (scope === Scope.Daemon && action === Action.Stop) {
    output(await daemonStop({ statePath }), jsonMode);
    return;
  }

  if (scope === Scope.Daemon && action === Action.Env && subaction === Action.Render) {
    output(
      await daemonRenderEnv({
        leaseId: getString(args, "lease"),
        mappings: resolveMappings({ maps: getStrings(args, "map"), projectFile }),
        sessionId: required(getString(args, "session"), "--session"),
        statePath,
      }),
      jsonMode,
    );
    return;
  }

  if (scope === Scope.Daemon && action === Action.Exec) {
    const result = await daemonExec({
      cmd: args.passthrough,
      leaseId: getString(args, "lease"),
      mappings: resolveMappings({ maps: getStrings(args, "map"), projectFile }),
      sessionId: required(getString(args, "session"), "--session"),
      statePath,
    });
    process.stdout.write(result.stdout);
    process.stderr.write(result.stderr);
    process.exit(result.exitCode);
  }

  if (scope === Scope.Recovery && action === Action.Generate) {
    const outputPath = absolutePath(required(getString(args, "output"), "--output"));
    const creds = await resolveUnlockCredentials(vaultPath, args, password);
    const { fileContent } = VaultService.generateRecovery(vaultPath, creds);
    writeFileSync(outputPath, fileContent, { encoding: "utf8", mode: 0o600 });
    if (!jsonMode) {
      console.log(`Recovery file written to ${outputPath}`);
      console.log("WARNING: Anyone with this file can open your vault. Store it offline.");
    } else {
      output({ outputPath, written: true }, jsonMode);
    }
    return;
  }

  if (scope === Scope.Recovery && action === Action.Revoke) {
    const creds = await resolveUnlockCredentials(vaultPath, args, password);
    VaultService.revokeRecovery(vaultPath, creds);
    output({ revoked: true }, jsonMode);
    return;
  }

  if (scope === Scope.Passkey && (action === Action.List || action === undefined)) {
    const passkeys = VaultService.listPasskeys(vaultPath);
    if (jsonMode) {
      output(passkeys.map(({ id, label, createdAt, transports }) => ({ createdAt, id, label, transports: transports ?? [] })), true);
    } else if (passkeys.length === 0) {
      console.log("No passkeys registered. Add one with `autho passkey add --label <name>`.");
    } else {
      for (const p of passkeys) {
        const via = p.transports?.length ? `  (${p.transports.join(", ")})` : "";
        console.log(`${p.id}  ${p.label}  added ${p.createdAt.slice(0, 10)}${via}`);
      }
    }
    return;
  }

  if (scope === Scope.Passkey && action === Action.Add) {
    // Prove access first, so a failed browser step doesn't waste a touch. The
    // handle outlives the ceremony, so a TOTP code can expire meanwhile.
    const admin = VaultService.authorize(vaultPath, await resolveUnlockCredentials(vaultPath, args, password));
    let info;
    try {
      const existing = VaultService.listPasskeys(vaultPath);
      const prfSalt = newPrfSalt();
      const result = await runPasskeyCeremony(
        {
          mode: "register",
          userName: `autho (${basename(vaultPath)})`,
          excludeCredentialIds: existing.map((p) => p.credentialId),
          prfSalt,
        },
        { onUrl: printCeremonyUrl },
      );
      const label = getString(args, "label") ?? (process.stdin.isTTY && !jsonMode ? (await readLine("Name for this passkey (e.g. YubiKey, MacBook): ")).trim() : "");
      info = admin.addPasskey({ ...result, label, prfSalt });
    } finally {
      admin.close();
      await saveSealRecord(vaultPath, admin.sealRecord());
    }
    if (jsonMode) {
      output({ added: true, id: info.id, label: info.label }, true);
    } else {
      console.log(`Added passkey "${info.label}" (${info.id}). Unlock with \`--passkey\` or ctrl+p in the TUI.`);
    }
    return;
  }

  if (scope === Scope.Passkey && (action === Action.Remove || action === Action.Rm)) {
    const ref = required(subaction ?? getString(args, "id"), "<id-or-label>");
    const creds = await resolveUnlockCredentials(vaultPath, args, password);
    const removed = VaultService.removePasskey(vaultPath, creds, ref);
    output({ id: removed.id, label: removed.label, removed: true }, jsonMode);
    return;
  }

  if (scope === Scope.Passkey) {
    throw new Error(`Unknown passkey action: ${action}. Use add, list or remove.`);
  }

  if (scope === Scope.Vault && action === Action.Reseal) {
    const mode = getBoolean(args, "accept") ? "accept" : "quarantine";
    const result = VaultService.reseal(vaultPath, await resolveUnlockCredentials(vaultPath, args, password), mode);
    await saveSealRecord(vaultPath, result.sealRecord);
    if (jsonMode) {
      output(result, true);
    } else if (result.wasIntact) {
      console.log("The vault seal is intact; nothing to do.");
    } else {
      if (result.reason) console.log(`Seal problem: ${result.reason}.`);
      printSealChanges(result.changes, result.diffTrusted);
      if (mode === "quarantine") {
        console.log(`Revoked ${result.revokedLeases} active lease(s).`);
        if (result.undone.length) console.log(`Undid ${result.undone.length} change(s).`);
        if (result.kept.length) {
          console.log(`Couldn't undo ${result.kept.length} change(s); check these by hand:`);
          printSealChanges(result.kept, true);
        }
      }
      console.log(mode === "accept" ? "Vault re-sealed as it is now." : "Vault re-sealed.");
    }
    return;
  }

  if (scope === Scope.Password && action === Action.Change) {
    const admin = VaultService.authorize(vaultPath, await resolveUnlockCredentials(vaultPath, args, password));
    try {
      let next = getString(args, "new-password") ?? process.env.AUTHO_NEW_MASTER_PASSWORD;
      if (!next && process.stdin.isTTY) {
        next = await readPasswordMasked("New master password: ");
        if (next !== await readPasswordMasked("Confirm new password: ")) {
          throw new Error("Passwords do not match — nothing changed");
        }
      }
      const newPassword = required(next, "--new-password");
      admin.changePassword(newPassword);
      // A saved keychain password would stop working, so keep it in step.
      const keychainUpdated = (await loadVaultPassword(vaultPath)) !== null && (await storeVaultPassword(vaultPath, newPassword));
      if (jsonMode) {
        output({ changed: true, keychainUpdated }, true);
      } else {
        console.log("Master password changed.");
        if (keychainUpdated) console.log(`The saved password in ${osKeychainName()} was updated too.`);
      }
    } finally {
      admin.close();
      await saveSealRecord(vaultPath, admin.sealRecord());
    }
    return;
  }

  if (scope === Scope.Password) {
    throw new Error(`Unknown password action: ${action}. Use: autho password change`);
  }

  if (scope === Scope.Unlock && getString(args, "recovery-file")) {
    const recoveryFilePath = absolutePath(getString(args, "recovery-file") as string);
    const content = readFileSync(recoveryFilePath, "utf8");
    // Extract token: find the line after "RECOVERY TOKEN:" and parse hex
    const lines = content.split("\n");
    const tokenLineIdx = lines.findIndex((l) => l.trim() === "RECOVERY TOKEN:");
    if (tokenLineIdx === -1) throw new Error("Invalid recovery file format");
    const rawTokenLine = lines.slice(tokenLineIdx + 1).find((l) => l.trim() !== "") ?? "";
    const token = rawTokenLine.replace(/-/g, "").toLowerCase();
    if (!token) throw new Error("Invalid recovery file format: missing token");
    const recoverySession = VaultService.unlock(vaultPath, { password: "", recovery: token });
    output({ unlocked: true, vaultPath }, jsonMode);
    recoverySession.close();
    return;
  }

  const creds = await resolveUnlockCredentials(vaultPath, args, password);
  const session = VaultService.unlock(vaultPath, creds);

  try {
    if (scope === Scope.Import && action === Action.Legacy) {
      output(
        session.importLegacyFile(absolutePath(required(getString(args, "file"), "--file")), {
          skipExisting: !getBoolean(args, "no-skip-existing"),
        }),
        jsonMode,
      );
      return;
    }

    if (scope === Scope.Secrets && action === Action.Add) {
      output(
        session.addSecret({
          metadata: buildSecretMetadata(args),
          name: required(getString(args, "name"), "--name"),
          type: required(getString(args, "type"), "--type"),
          username: getString(args, "username"),
          value: required(getString(args, "value"), "--value"),
        }),
        jsonMode,
      );
      return;
    }

    if (scope === Scope.Secrets && action === Action.List) {
      output(session.listSecrets(), jsonMode);
      return;
    }

    if (scope === Scope.Secrets && action === Action.Get) {
      const ref = required(getString(args, "ref") ?? getString(args, "name") ?? getString(args, "id"), "--ref");
      const secret = session.getSecret(ref);
      output(getBoolean(args, "links") ? { ...secret, ...session.getLinks(secret.id) } : secret, jsonMode);
      return;
    }

    if (scope === Scope.Secrets && action === Action.Rm) {
      const ref = getString(args, "ref") ?? getString(args, "name") ?? getString(args, "id");
      output(session.removeSecret(required(ref, "--ref"), { withLinked: getBoolean(args, "with-linked") }), jsonMode);
      return;
    }

    if (scope === Scope.Link || scope === Scope.Unlink) {
      // autho link <primary> <secret>, or --primary/--secret
      const primary = required(action ?? getString(args, "primary"), "<primary>");
      const linked = required(subaction ?? getString(args, "secret"), "<secret>");
      output(scope === Scope.Link ? session.linkSecrets(primary, linked) : session.unlinkSecrets(primary, linked), jsonMode);
      return;
    }

    if (scope === Scope.Vault && action === Action.Verify) {
      const seal = session.verifySeal();
      if (jsonMode) {
        output(seal, true);
      } else if (seal.state === "intact") {
        console.log("Vault seal is intact.");
      } else if (seal.state === "unsealed") {
        console.log("Vault isn't sealed yet. Unlock it with the master password to seal it.");
      } else {
        console.log(`Vault was modified outside autho: ${seal.reason}.`);
        printSealChanges(seal.changes, seal.diffTrusted);
        console.log("Run `autho vault reseal` to undo the changes and revoke leases, or `autho vault reseal --accept` if you made the change.");
      }
      if (seal.state === "tampered") process.exitCode = 2;
      return;
    }

    if (scope === Scope.Lease && action === Action.Show) {
      output(session.showLease(required(getString(args, "lease"), "--lease")), jsonMode);
      return;
    }

    if (scope === Scope.Secrets && action === Action.Edit) {
      const ref = getString(args, "ref") ?? getString(args, "name") ?? getString(args, "id");
      const updates: Record<string, string | Record<string, unknown> | undefined> = {};
      if (getString(args, "new-name")) updates.name = getString(args, "new-name");
      if (getString(args, "value")) updates.value = getString(args, "value");
      if (getString(args, "username")) updates.username = getString(args, "username");
      if (getString(args, "type")) updates.type = getString(args, "type");
      const meta = buildSecretMetadata(args);
      if (Object.keys(meta).length > 0) updates.metadata = meta;
      output(session.updateSecret(required(ref, "--ref"), updates), jsonMode);
      return;
    }

    if (scope === Scope.Otp && action === Action.Code) {
      const ref = getString(args, "ref") ?? getString(args, "name") ?? getString(args, "id");
      output(session.generateOtp(required(ref, "--ref")), jsonMode);
      return;
    }

    if (scope === Scope.Lease && action === Action.Create) {
      output(
        session.createLease({
          name: getString(args, "name") ?? "session",
          noLinks: getBoolean(args, "no-links"),
          secretRefs: getStrings(args, "secret"),
          ttlSeconds: leaseTtl(args),
        }),
        jsonMode,
      );
      return;
    }

    if (scope === Scope.Lease && action === Action.Revoke) {
      output(session.revokeLease(required(getString(args, "lease"), "--lease")), jsonMode);
      return;
    }

    if (scope === Scope.Env && action === Action.Render) {
      output(
        session.renderEnv(
          resolveMappings({
            maps: getStrings(args, "map"),
            projectFile,
          }),
          getString(args, "lease"),
        ),
        jsonMode,
      );
      return;
    }

    if (scope === Scope.Env && action === Action.Sync) {
      output(
        session.syncEnvFile({
          force: getBoolean(args, "force"),
          leaseId: getString(args, "lease"),
          mappings: resolveMappings({
            maps: getStrings(args, "map"),
            projectFile,
          }),
          outputPath: absolutePath(getString(args, "output") ?? ".env.autho"),
          ttlSeconds: getString(args, "ttl") ? requirePositiveInt(getString(args, "ttl") as string, "--ttl") : undefined,
        }),
        jsonMode,
      );
      return;
    }

    if (scope === Scope.Exec) {
      const result = session.runExec({
        cmd: args.passthrough,
        leaseId: getString(args, "lease"),
        mappings: resolveMappings({
          maps: getStrings(args, "map"),
          projectFile,
        }),
      });
      process.stdout.write(result.stdout);
      process.stderr.write(result.stderr);
      process.exit(result.exitCode);
    }

    if (scope === Scope.File && action === Action.Encrypt) {
      output(
        session.encryptFile(
          absolutePath(required(getString(args, "input"), "--input")),
          getString(args, "output") ? absolutePath(getString(args, "output") as string) : undefined,
          { force: getBoolean(args, "force") },
        ),
        jsonMode,
      );
      return;
    }

    if (scope === Scope.File && action === Action.Decrypt) {
      output(
        session.decryptFile(
          absolutePath(required(getString(args, "input"), "--input")),
          getString(args, "output") ? absolutePath(getString(args, "output") as string) : undefined,
          { force: getBoolean(args, "force") },
        ),
        jsonMode,
      );
      return;
    }

    if (scope === Scope.Files && action === Action.Encrypt) {
      output(
        session.encryptFolder(
          absolutePath(required(getString(args, "input"), "--input")),
          getString(args, "output") ? absolutePath(getString(args, "output") as string) : undefined,
          { force: getBoolean(args, "force") },
        ),
        jsonMode,
      );
      return;
    }

    if (scope === Scope.Files && action === Action.Decrypt) {
      output(
        session.decryptFolder(
          absolutePath(required(getString(args, "input"), "--input")),
          getString(args, "output") ? absolutePath(getString(args, "output") as string) : undefined,
          { force: getBoolean(args, "force") },
        ),
        jsonMode,
      );
      return;
    }

    if (scope === Scope.Audit && action === Action.List) {
      output(session.listAudit(Number(getString(args, "limit") ?? "50")), jsonMode);
      return;
    }

    throw new Error(`Unknown command: ${[scope, action, subaction].filter(Boolean).join(" ")}`);
  } finally {
    await closeSessionAndRecordSeal(vaultPath, session);
  }
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(message);
  process.exit(1);
});

