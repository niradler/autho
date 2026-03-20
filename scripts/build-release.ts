#!/usr/bin/env bun
/**
 * Build a compiled binary for the current platform.
 * Cross-platform builds run via GitHub Actions (see .github/workflows/release.yml).
 *
 * Usage: bun run scripts/build-release.ts
 */

import { $ } from "bun";
import { mkdir } from "node:fs/promises";

const CLI_ENTRY = "./apps/cli/src/index.ts";
const platform = process.platform === "win32" ? "windows" : process.platform;
const arch = process.arch === "arm64" ? "arm64" : "x64";
const ext = platform === "windows" ? ".exe" : "";
const target = `bun-${platform}-${arch}`;
const outfile = `dist/autho-${platform}-${arch}${ext}`;

await mkdir("dist", { recursive: true });

console.log(`Building ${target} → ${outfile}`);
await $`bun build ${CLI_ENTRY} --compile --minify --target=${target} --outfile=${outfile}`;

console.log(`\nValidating...`);
await $`${outfile} help`;

console.log(`\nDone: ${outfile}`);
