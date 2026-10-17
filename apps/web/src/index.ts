#!/usr/bin/env bun

import { startWebServer } from "./server.ts";

function parseArgs(argv: string[]): { options: Record<string, string | boolean>; positionals: string[] } {
  const options: Record<string, string | boolean> = {};
  const positionals: string[] = [];

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
    throw new Error("Web server supports only: serve");
  }
  const port = getString(args.options, "port");
  await startWebServer({
    host: getString(args.options, "host"),
    port: port === undefined ? undefined : Number(port),
    vaultPath: getString(args.options, "vault"),
  });
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
