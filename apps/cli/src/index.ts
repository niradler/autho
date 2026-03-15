#!/usr/bin/env bun

import { resolve } from "node:path";

import {
  VaultService,
  defaultVaultPath,
  resolveMappings,
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

function output(value: unknown, json = false): void {
  if (json) {
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

function help(): string {
  return [
    "Autho rewrite CLI",
    "",
    "Commands:",
    "  init --password <value> [--vault <path>]",
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
    "  The default vault path is ./.autho/vault.db",
    "  AUTHO_MASTER_PASSWORD can be used instead of --password",
  ].join("\n");
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const [scope, action] = args.positionals;
  const json = getBoolean(args, "json");
  const vaultPath = getString(args, "vault") ?? defaultVaultPath();
  const password = getString(args, "password") ?? process.env.AUTHO_MASTER_PASSWORD;

  if (!scope || scope === "help" || scope === "--help") {
    console.log(help());
    return;
  }

  if (scope === "init") {
    const result = VaultService.initialize(vaultPath, required(password, "--password"));
    output(result, json);
    return;
  }

  const session = VaultService.unlock(vaultPath, required(password, "--password"));

  try {
    if (scope === "import" && action === "legacy") {
      output(
        session.importLegacyFile(absolutePath(required(getString(args, "file"), "--file")), {
          skipExisting: getBoolean(args, "skip-existing") || !getBoolean(args, "no-skip-existing"),
        }),
        json,
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
        json,
      );
      return;
    }

    if (scope === "secrets" && action === "list") {
      output(session.listSecrets(), json);
      return;
    }

    if (scope === "secrets" && action === "get") {
      const ref = getString(args, "ref") ?? getString(args, "name") ?? getString(args, "id");
      output(session.getSecret(required(ref, "--ref")), json);
      return;
    }

    if (scope === "secrets" && action === "rm") {
      const ref = getString(args, "ref") ?? getString(args, "name") ?? getString(args, "id");
      output(session.removeSecret(required(ref, "--ref")), json);
      return;
    }

    if (scope === "otp" && action === "code") {
      const ref = getString(args, "ref") ?? getString(args, "name") ?? getString(args, "id");
      output(session.generateOtp(required(ref, "--ref")), json);
      return;
    }

    if (scope === "lease" && action === "create") {
      output(
        session.createLease({
          name: getString(args, "name") ?? "session",
          secretRefs: getStrings(args, "secret"),
          ttlSeconds: Number(required(getString(args, "ttl"), "--ttl")),
        }),
        json,
      );
      return;
    }

    if (scope === "lease" && action === "revoke") {
      output(
        session.revokeLease(required(getString(args, "lease"), "--lease")),
        json,
      );
      return;
    }

    if (scope === "env" && action === "render") {
      output(
        session.renderEnv(
          resolveMappings({
            maps: getStrings(args, "map"),
            projectFile: getString(args, "project-file"),
          }),
          getString(args, "lease"),
        ),
        json,
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
            projectFile: getString(args, "project-file"),
          }),
          outputPath: absolutePath(getString(args, "output") ?? ".env.autho"),
          ttlSeconds: getString(args, "ttl") ? Number(getString(args, "ttl")) : undefined,
        }),
        json,
      );
      return;
    }

    if (scope === "exec") {
      const result = session.runExec({
        cmd: args.passthrough,
        leaseId: getString(args, "lease"),
        mappings: resolveMappings({
          maps: getStrings(args, "map"),
          projectFile: getString(args, "project-file"),
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
        json,
      );
      return;
    }

    if (scope === "file" && action === "decrypt") {
      output(
        session.decryptFile(
          absolutePath(required(getString(args, "input"), "--input")),
          getString(args, "output") ? absolutePath(getString(args, "output") as string) : undefined,
        ),
        json,
      );
      return;
    }

    if (scope === "files" && action === "encrypt") {
      output(
        session.encryptFolder(
          absolutePath(required(getString(args, "input"), "--input")),
          getString(args, "output") ? absolutePath(getString(args, "output") as string) : undefined,
        ),
        json,
      );
      return;
    }

    if (scope === "files" && action === "decrypt") {
      output(
        session.decryptFolder(
          absolutePath(required(getString(args, "input"), "--input")),
          getString(args, "output") ? absolutePath(getString(args, "output") as string) : undefined,
        ),
        json,
      );
      return;
    }

    if (scope === "audit" && action === "list") {
      output(
        session.listAudit(Number(getString(args, "limit") ?? "50")),
        json,
      );
      return;
    }

    throw new Error(`Unknown command: ${[scope, action].filter(Boolean).join(" ")}`);
  } finally {
    session.close();
  }
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(message);
  process.exit(1);
});
