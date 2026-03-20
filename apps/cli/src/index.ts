#!/usr/bin/env bun

import { spawn } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { createInterface } from "node:readline/promises";
import { resolve } from "node:path";
import { readPasswordMasked } from "./password.ts";

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
  type UnlockCredentials,
  defaultProjectFilePath,
  defaultVaultPath,
  resolveMappings,
  writeProjectConfig,
} from "../../../packages/core/src/index.ts";
import {
  deleteOsSecret,
  getOsSecret,
  hasPinSet,
  loadVaultPassword,
  setOsSecret,
  storePinHash,
  storeVaultPassword,
  verifyPin,
  deletePin,
} from "../../../packages/core/src/os-secrets.ts";

type ParsedArgs = {
  options: Record<string, boolean | string | string[]>;
  passthrough: string[];
  positionals: string[];
};

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
    const session = VaultService.unlock(vaultPath, password);
    try {
      const action = (await prompt.ask("Action [create/read/list/delete/otp/exit]: ")).toLowerCase();

      if (action === "exit") {
        return;
      }

      if (action === "list") {
        output(session.listSecrets());
        return;
      }

      if (action === "read") {
        const ref = await prompt.ask("Secret ref: ");
        output(session.getSecret(ref));
        return;
      }

      if (action === "delete") {
        const ref = await prompt.ask("Secret ref: ");
        output(session.removeSecret(ref));
        return;
      }

      if (action === "otp") {
        const ref = await prompt.ask("OTP ref: ");
        output(session.generateOtp(ref));
        return;
      }

      if (action === "create") {
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
      session.close();
    }
  } finally {
    prompt.close();
  }
}
async function resolveUnlockCredentials(
  vaultPath: string,
  args: ParsedArgs,
  existingPassword?: string,
): Promise<UnlockCredentials> {
  // Password: --password > AUTHO_MASTER_PASSWORD > OS keychain > interactive prompt
  let password = existingPassword ?? getString(args, "password") ?? process.env.AUTHO_MASTER_PASSWORD;
  if (!password) {
    password = (await loadVaultPassword(vaultPath)) ?? undefined;
  }
  if (!password && process.stdin.isTTY) {
    password = await readPasswordMasked("Master password: ");
  }

  const creds: UnlockCredentials = { password: required(password, "--password") };

  // PIN check (if set on this machine)
  if (await hasPinSet(vaultPath)) {
    const pin = process.stdin.isTTY
      ? await readPasswordMasked("PIN: ")
      : getString(args, "pin");
    if (!pin) throw new Error("PIN is set on this vault — provide it interactively or with --pin");
    const ok = await verifyPin(vaultPath, pin);
    if (!ok) throw new Error("Wrong PIN");
  }

  // TOTP check (if enabled in vault)
  const authConfig = VaultService.getAuthConfig(vaultPath);
  if (authConfig?.totp) {
    const totp = process.stdin.isTTY
      ? await readPasswordMasked("Authenticator code: ")
      : getString(args, "totp");
    if (!totp) throw new Error("TOTP is enabled — provide a 6-digit code interactively or with --totp");
    creds.totp = totp;
  }

  return creds;
}

async function runInitWizard(vaultPath: string, password: string, existingCreds?: UnlockCredentials): Promise<void> {
  const isReconfigure = existingCreds !== undefined;
  const creds: UnlockCredentials = existingCreds ?? { password };

  while (true) {
    const authConfig = VaultService.getAuthConfig(vaultPath);
    const pinSet = await hasPinSet(vaultPath);
    const totpEnabled = authConfig?.totp !== undefined;

    console.log("");
    if (isReconfigure) {
      console.log("Security factors:");
    } else {
      console.log("Configure security factors (you can change these anytime with: autho init)");
    }
    console.log(`  [P] PIN  — ${pinSet ? "SET on this machine" : "not set"}   → toggle`);
    console.log(`  [T] TOTP — ${totpEnabled ? "ENABLED" : "not enabled"}   → toggle`);
    console.log("  [S] Done");
    console.log("");

    const choice = (await readPasswordMasked("Choice [P/T/S]: ")).trim().toUpperCase();

    if (choice === "S" || choice === "") {
      console.log("Security configuration complete.");
      break;
    }

    if (choice === "P") {
      if (pinSet) {
        // Remove PIN
        const confirmPin = await readPasswordMasked("Enter current PIN to confirm removal: ");
        const ok = await verifyPin(vaultPath, confirmPin);
        if (!ok) { console.log("Wrong PIN, not removed."); continue; }
        await deletePin(vaultPath);
        console.log("PIN removed from this machine.");
      } else {
        // Set PIN
        const newPin = await readPasswordMasked("New PIN: ");
        if (!newPin) { console.log("PIN cannot be empty."); continue; }
        const confirmPin = await readPasswordMasked("Confirm PIN: ");
        if (newPin !== confirmPin) { console.log("PINs do not match."); continue; }
        await storePinHash(vaultPath, newPin);
        console.log("PIN set. You will be prompted for it on this machine before unlocking.");
      }
    } else if (choice === "T") {
      if (totpEnabled) {
        // Remove TOTP
        const totpCode = await readPasswordMasked("Enter current TOTP code to confirm removal: ");
        const removeCreds: UnlockCredentials = { ...creds, totp: totpCode };
        try {
          VaultService.removeTotp(vaultPath, removeCreds);
          console.log("TOTP disabled.");
        } catch (e) {
          console.log(`Error: ${e instanceof Error ? e.message : String(e)}`);
        }
      } else {
        // Enable TOTP
        const { secret, uri } = VaultService.setupTotp(vaultPath);
        console.log("");
        console.log("TOTP Secret:", secret);
        console.log("Scan in your authenticator app:");
        console.log(uri);
        console.log("");
        const code = await readPasswordMasked("Enter the 6-digit code to confirm: ");
        try {
          VaultService.enableTotp(vaultPath, creds, secret, code);
          console.log("TOTP enabled. You will need your authenticator app to unlock this vault.");
        } catch (e) {
          console.log(`Error: ${e instanceof Error ? e.message : String(e)}`);
        }
      }
    } else {
      console.log("Unknown choice. Enter P, T, or S.");
    }
  }
}

async function runWebServer(vaultPath: string, args: ParsedArgs): Promise<void> {
  const commandArgs = [
    "run",
    absolutePath("./apps/web/src/index.ts"),
    "serve",
    "--vault",
    absolutePath(vaultPath),
  ];

  const host = getString(args, "host");
  const port = getString(args, "port");
  if (host) {
    commandArgs.push("--host", host);
  }
  if (port) {
    commandArgs.push("--port", port);
  }

  await new Promise<void>((resolvePromise, rejectPromise) => {
    const child = spawn(process.execPath, commandArgs, {
      cwd: process.cwd(),
      stdio: "inherit",
    });
    child.on("exit", (code) => {
      if (code === 0) {
        resolvePromise();
        return;
      }
      rejectPromise(new Error(`Web server exited with code ${code ?? 1}`));
    });
    child.on("error", rejectPromise);
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
    "  secrets get --ref <name-or-id> [--vault <path>] [--json]",
    "  secrets rm --ref <name-or-id> [--vault <path>] [--json]",
    "  secrets edit --ref <name-or-id> [--new-name <v>] [--value <v>] [--username <v>] [--url <v>] [--description <v>] [--vault <path>] [--json]",
    "  otp code --ref <name-or-id> [--vault <path>] [--json]",
    "  lease create --secret <ref> [--secret <ref>] --ttl <seconds> [--name <v>] [--vault <path>] [--json]",
    "  lease revoke --lease <id> [--vault <path>] [--json]",
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
    "  os-secrets set --name <name> [--value <value>] [--json]",
    "  os-secrets get --name <name> [--json]",
    "  os-secrets delete --name <name> [--json]",
    "",
    "Authentication:",
    "  When running interactively (TTY), you will be securely prompted for your",
    "  master password with masked input (no --password flag needed).",
    "",
    "  For automation and coding agents, use one of:",
    "    autho init (or rerun)             Stores master password in the native OS secret store automatically",
    "    AUTHO_MASTER_PASSWORD=<value>    Environment variable",
    "    --password <value>               CLI flag (visible in shell history - avoid!)",
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
    "  The default vault path is ~/.autho/vault.db (override with AUTHO_HOME).",
    "  The default project file is ~/.autho/project.json.",
    "  The default daemon state file is ~/.autho/daemon.json.",
  ].join("\n");
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const [scope, action, subaction] = args.positionals;
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

  if (scope === "help" || scope === "--help") {
    console.log(help());
    return;
  }

  if (scope === "prompt") {
    await runPromptMode(vaultPath, password);
    return;
  }

  // Auto-prompt for password when running interactively and no --password/env var
  if (!password && process.stdin.isTTY) {
    const needsPassword = [
      "secrets", "otp", "lease", "env", "exec",
      "file", "files", "audit", "import", "recovery", "unlock",
    ].includes(scope);
    const daemonNeedsPassword = scope === "daemon" && action === "unlock";
    if (needsPassword || daemonNeedsPassword) {
      password = await readPasswordMasked("Master password: ");
    }
  }

  if (scope === "init") {
    const existingStatus = VaultService.status(vaultPath);

    if (!existingStatus.initialized) {
      // First run: create vault
      const pw = required(password, "--password");
      output(VaultService.initialize(vaultPath, pw), jsonMode);
      const stored = await storeVaultPassword(vaultPath, pw);
      if (stored && !jsonMode) {
        console.log("Master password saved to OS secret store. You won't be prompted again on this machine.");
      }

      // Security wizard (TTY only, not in --json mode)
      if (process.stdin.isTTY && !jsonMode) {
        await runInitWizard(vaultPath, pw);
      }
    } else {
      // Reconfigure: full security check first
      const creds = await resolveUnlockCredentials(vaultPath, args, password);
      // Credentials verified — now run wizard
      if (process.stdin.isTTY && !jsonMode) {
        await runInitWizard(vaultPath, creds.password, creds);
      } else {
        console.log("Vault already initialized. Use interactive mode (TTY) to reconfigure security factors.");
      }
    }
    return;
  }

  if (scope === "status") {
    output(
      VaultService.status(vaultPath, {
        password,
        projectFile,
      }),
      jsonMode,
    );
    return;
  }

  if (scope === "project" && action === "init") {
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

  if (scope === "os-secrets" && action === "set") {
    const name = required(getString(args, "name"), "--name");
    const value = getString(args, "value") ?? await readPasswordMasked(`Value for "${name}": `);
    const stored = await setOsSecret(name, value);
    if (!stored) {
      throw new Error("OS secret store is unavailable on this system (try AUTHO_DISABLE_OS_SECRETS=1 to confirm, or check that a secret service daemon is running on Linux)");
    }
    output({ name, stored: true }, jsonMode);
    return;
  }

  if (scope === "os-secrets" && action === "get") {
    const name = required(getString(args, "name"), "--name");
    const value = await getOsSecret(name);
    if (value === null) {
      throw new Error(`Secret "${name}" not found in OS secret store`);
    }
    output({ name, value }, jsonMode);
    return;
  }

  if (scope === "os-secrets" && action === "delete") {
    const name = required(getString(args, "name"), "--name");
    const deleted = await deleteOsSecret(name);
    output({ deleted, name }, jsonMode);
    return;
  }

  if (scope === "web" && action === "serve") {
    await runWebServer(vaultPath, args);
    return;
  }

  if (scope === "daemon" && action === "serve") {
    await startDaemonServer({
      host: getString(args, "host") ?? "127.0.0.1",
      port: Number(getString(args, "port") ?? "0"),
      statePath,
      vaultPath: absolutePath(vaultPath),
    });
    return;
  }

  if (scope === "daemon" && action === "status") {
    output(await daemonStatus({ statePath }), jsonMode);
    return;
  }

  if (scope === "daemon" && action === "unlock") {
    output(
      await daemonUnlock({
        password: required(password, "--password"),
        statePath,
        ttlSeconds: getString(args, "ttl") ? Number(getString(args, "ttl")) : undefined,
      }),
      jsonMode,
    );
    return;
  }

  if (scope === "daemon" && action === "lock") {
    output(
      await daemonLock({
        sessionId: required(getString(args, "session"), "--session"),
        statePath,
      }),
      jsonMode,
    );
    return;
  }

  if (scope === "daemon" && action === "stop") {
    output(await daemonStop({ statePath }), jsonMode);
    return;
  }

  if (scope === "daemon" && action === "env" && subaction === "render") {
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

  if (scope === "daemon" && action === "exec") {
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

  if (scope === "recovery" && action === "generate") {
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

  if (scope === "recovery" && action === "revoke") {
    const creds = await resolveUnlockCredentials(vaultPath, args, password);
    VaultService.revokeRecovery(vaultPath, creds);
    output({ revoked: true }, jsonMode);
    return;
  }

  if (scope === "unlock" && getString(args, "recovery-file")) {
    const recoveryFilePath = absolutePath(getString(args, "recovery-file") as string);
    const content = readFileSync(recoveryFilePath, "utf8");
    // Extract token: find the line after "RECOVERY TOKEN:" and parse hex
    const lines = content.split("\n");
    const tokenLineIdx = lines.findIndex((l) => l.trim() === "RECOVERY TOKEN:");
    if (tokenLineIdx === -1) throw new Error("Invalid recovery file format");
    const tokenLine = lines[tokenLineIdx + 1]?.trim() ?? "";
    // Token is formatted as hex uppercase with dashes e.g. "ABCD1234-EFGH5678-..."
    const token = tokenLine.replace(/-/g, "").toLowerCase();
    const recoverySession = VaultService.unlock(vaultPath, { password: "", recovery: token });
    output({ unlocked: true, vaultPath }, jsonMode);
    recoverySession.close();
    return;
  }

  const creds = await resolveUnlockCredentials(vaultPath, args, password);
  const session = VaultService.unlock(vaultPath, creds);

  try {
    if (scope === "import" && action === "legacy") {
      output(
        session.importLegacyFile(absolutePath(required(getString(args, "file"), "--file")), {
          skipExisting: !getBoolean(args, "no-skip-existing"),
        }),
        jsonMode,
      );
      return;
    }

    if (scope === "secrets" && action === "add") {
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

    if (scope === "secrets" && action === "list") {
      output(session.listSecrets(), jsonMode);
      return;
    }

    if (scope === "secrets" && action === "get") {
      const ref = getString(args, "ref") ?? getString(args, "name") ?? getString(args, "id");
      output(session.getSecret(required(ref, "--ref")), jsonMode);
      return;
    }

    if (scope === "secrets" && action === "rm") {
      const ref = getString(args, "ref") ?? getString(args, "name") ?? getString(args, "id");
      output(session.removeSecret(required(ref, "--ref")), jsonMode);
      return;
    }

    if (scope === "secrets" && action === "edit") {
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

    if (scope === "otp" && action === "code") {
      const ref = getString(args, "ref") ?? getString(args, "name") ?? getString(args, "id");
      output(session.generateOtp(required(ref, "--ref")), jsonMode);
      return;
    }

    if (scope === "lease" && action === "create") {
      output(
        session.createLease({
          name: getString(args, "name") ?? "session",
          secretRefs: getStrings(args, "secret"),
          ttlSeconds: requirePositiveInt(required(getString(args, "ttl"), "--ttl"), "--ttl"),
        }),
        jsonMode,
      );
      return;
    }

    if (scope === "lease" && action === "revoke") {
      output(session.revokeLease(required(getString(args, "lease"), "--lease")), jsonMode);
      return;
    }

    if (scope === "env" && action === "render") {
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

    if (scope === "env" && action === "sync") {
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

    if (scope === "exec") {
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

    if (scope === "file" && action === "encrypt") {
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

    if (scope === "file" && action === "decrypt") {
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

    if (scope === "files" && action === "encrypt") {
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

    if (scope === "files" && action === "decrypt") {
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

    if (scope === "audit" && action === "list") {
      output(session.listAudit(Number(getString(args, "limit") ?? "50")), jsonMode);
      return;
    }

    throw new Error(`Unknown command: ${[scope, action, subaction].filter(Boolean).join(" ")}`);
  } finally {
    session.close();
  }
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(message);
  process.exit(1);
});

