#!/usr/bin/env bun

import { resolve } from "node:path";

import {
  defaultDaemonStatePath,
  startDaemonServer,
} from "../../../packages/core/src/daemon.ts";
import { defaultVaultPath } from "../../../packages/core/src/index.ts";

function parseArgs(argv: string[]): {
  options: Record<string, string | boolean>;
  positionals: string[];
} {
  const positionals: string[] = [];
  const options: Record<string, string | boolean> = {};

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith("--")) {
      positionals.push(token);
      continue;
    }

    const key = token.slice(2);
    const next = argv[index + 1];
    if (!next || next.startsWith("--")) {
      options[key] = true;
      continue;
    }

    options[key] = next;
    index += 1;
  }

  return { options, positionals };
}

function getString(options: Record<string, string | boolean>, key: string): string | undefined {
  const value = options[key];
  return typeof value === "string" ? value : undefined;
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const [command] = args.positionals;

  if (command !== "serve") {
    throw new Error("Daemon supports only: serve");
  }

  await startDaemonServer({
    host: getString(args.options, "host") ?? "127.0.0.1",
    port: Number(getString(args.options, "port") ?? "0"),
    statePath: resolve(getString(args.options, "state-file") ?? defaultDaemonStatePath()),
    vaultPath: resolve(getString(args.options, "vault") ?? defaultVaultPath()),
  });
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
