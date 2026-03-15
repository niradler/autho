#!/usr/bin/env bun

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { createInterface } from "node:readline/promises";
import { resolve } from "node:path";

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
  defaultProjectFilePath,
  defaultVaultPath,
  resolveMappings,
  writeProjectConfig,
} from "../../../packages/core/src/index.ts";

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
    "Autho Bun CLI",
    "",
    "Commands:",
    "  prompt [--password <value>] [--vault <path>]",
    "  init --password <value> [--vault <path>]",
    "  status [--password <value>] [--vault <path>] [--project-file <path>] [--json]",
    "  project init --map <ENV_NAME=secretRef> [--map <ENV_NAME=secretRef>] [--output <path>] [--force] [--json]",
    "  web serve [--vault <path>] [--host <value>] [--port <value>]",
    "  daemon serve [--vault <path>] [--state-file <path>] [--host <value>] [--port <value>]",
    "  daemon status [--state-file <path>] [--json]",
    "  daemon unlock --password <value> [--ttl <seconds>] [--state-file <path>] [--json]",
    "  daemon lock --session <id> [--state-file <path>] [--json]",
    "  daemon stop [--state-file <path>] [--json]",
    "  daemon env render --session <id> --map <ENV_NAME=secretRef> [--project-file <path>] [--lease <lease-id>] [--state-file <path>] [--json]",
    "  daemon exec --session <id> --map <ENV_NAME=secretRef> [--project-file <path>] [--lease <lease-id>] [--state-file <path>] -- <command>",
    "  import legacy --password <value> --file <path> [--skip-existing] [--vault <path>] [--json]",
    "  secrets add --password <value> --name <name> --type <password|note|otp> --value <value> [--username <value>] [--url <value>] [--description <value>] [--digits <value>] [--algorithm <value>] [--vault <path>]",
    "  secrets list --password <value> [--vault <path>] [--json]",
    "  secrets get --password <value> --ref <name-or-id> [--vault <path>] [--json]",
    "  secrets rm --password <value> --ref <name-or-id> [--vault <path>] [--json]",
    "  otp code --password <value> --ref <name-or-id> [--vault <path>] [--json]",
    "  lease create --password <value> --secret <name-or-id> [--secret <name-or-id>] --ttl <seconds> [--name <value>] [--vault <path>] [--json]",
    "  lease revoke --password <value> --lease <lease-id> [--vault <path>] [--json]",
    "  env render --password <value> --map <ENV_NAME=secretRef> [--map <ENV_NAME=secretRef>] [--project-file <path>] [--lease <lease-id>] [--vault <path>] [--json]",
    "  env sync --password <value> --map <ENV_NAME=secretRef> [--project-file <path>] [--lease <lease-id>] [--ttl <seconds>] [--output <path>] [--force] [--vault <path>] [--json]",
    "  exec --password <value> --map <ENV_NAME=secretRef> [--project-file <path>] [--lease <lease-id>] [--vault <path>] -- <command>",
    "  file encrypt --password <value> --input <path> [--output <path>] [--vault <path>] [--json]",
    "  file decrypt --password <value> --input <path> [--output <path>] [--vault <path>] [--json]",
    "  files encrypt --password <value> --input <path> [--output <path>] [--vault <path>] [--json]",
    "  files decrypt --password <value> --input <path> [--output <path>] [--vault <path>] [--json]",
    "  audit list --password <value> [--limit <number>] [--vault <path>] [--json]",
    "",
    "Notes:",
    "  Running `autho` with no command enters interactive prompt mode.",
    "  The default vault path is ~/.autho/vault.db (or AUTHO_HOME/vault.db).",
    "  The default project file is ~/.autho/project.json when it exists (or AUTHO_HOME/project.json).",
    "  The default daemon state file is ~/.autho/daemon.json (or AUTHO_HOME/daemon.json).",
    "  AUTHO_MASTER_PASSWORD can be used instead of --password.",
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
  const password = getString(args, "password") ?? process.env.AUTHO_MASTER_PASSWORD;

  if (!scope) {
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

  if (scope === "init") {
    output(VaultService.initialize(vaultPath, required(password, "--password")), jsonMode);
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

  const session = VaultService.unlock(vaultPath, required(password, "--password"));

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

