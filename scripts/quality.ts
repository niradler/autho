import { mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, extname, join, relative } from "node:path";

const repoRoot = process.cwd();
const sourceRoots = ["apps", "packages", "scripts", "tests"];
const textExtensions = new Set([".json", ".md", ".ts", ".yml", ".yaml"]);
const ignoredDirs = new Set([".codex-tmp", ".git", "dist", "node_modules", "tmp"]);

type QualityMode = "format:check" | "format:write" | "lint" | "typecheck";

function walk(root: string): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    if (ignoredDirs.has(entry.name)) {
      continue;
    }
    const fullPath = join(root, entry.name);
    if (entry.isDirectory()) {
      files.push(...walk(fullPath));
      continue;
    }
    if (entry.isFile()) {
      files.push(fullPath);
    }
  }
  return files;
}

function sourceFiles(): string[] {
  return sourceRoots
    .flatMap((root) => (statSafe(root) ? walk(join(repoRoot, root)) : []))
    .filter((file) => textExtensions.has(extname(file)) || basename(file) === "package.json");
}

function statSafe(path: string): boolean {
  try {
    return statSync(join(repoRoot, path)).isDirectory();
  } catch {
    return false;
  }
}

function normalizeText(content: string): string {
  const unified = content.replace(/\r\n/g, "\n");
  const strippedTrailingWhitespace = unified
    .split("\n")
    .map((line) => line.replace(/[ \t]+$/g, ""))
    .join("\n");

  return strippedTrailingWhitespace.endsWith("\n")
    ? strippedTrailingWhitespace
    : `${strippedTrailingWhitespace}\n`;
}

function formatCheck(write = false): void {
  const violations: string[] = [];

  for (const file of sourceFiles()) {
    const content = readFileSync(file, "utf8");
    const normalized = normalizeText(content);
    if (content !== normalized) {
      violations.push(relative(repoRoot, file));
      if (write) {
        mkdirSync(dirname(file), { recursive: true });
        writeFileSync(file, normalized, "utf8");
      }
    }
  }

  if (!write && violations.length > 0) {
    throw new Error(
      `Formatting violations in:\n${violations.map((file) => `- ${file}`).join("\n")}`,
    );
  }
}

function lintCheck(): void {
  const violations: string[] = [];

  for (const file of sourceFiles()) {
    const relativePath = relative(repoRoot, file).replace(/\\/g, "/");
    const content = readFileSync(file, "utf8");

    if (content.includes("\t")) {
      violations.push(`${relativePath}: tab indentation is not allowed`);
    }
    if (/^<<<<<<<|^>>>>>>>/m.test(content)) {
      violations.push(`${relativePath}: merge conflict markers detected`);
    }
    if (/@ts-ignore\b/.test(content) && !relativePath.endsWith("scripts/quality.ts")) {
      violations.push(`${relativePath}: @ts-ignore is not allowed`);
    }
    if (relativePath.startsWith("packages/") && /\bany\b/.test(content)) {
      violations.push(`${relativePath}: avoid 'any' in core packages`);
    }
    if (
      relativePath.startsWith("packages/") &&
      /console\.(log|error|warn)\(/.test(content)
    ) {
      violations.push(`${relativePath}: console usage is not allowed in core packages`);
    }
  }

  if (violations.length > 0) {
    throw new Error(violations.map((entry) => `- ${entry}`).join("\n"));
  }
}

async function typecheck(): Promise<void> {
  const builds = [
    Bun.build({
      entrypoints: ["./apps/cli/src/index.ts"],
      outdir: "./tmp/quality/cli",
      target: "bun",
    }),
    Bun.build({
      entrypoints: ["./apps/daemon/src/index.ts"],
      outdir: "./tmp/quality/daemon",
      target: "bun",
    }),
    Bun.build({
      entrypoints: ["./apps/web/src/index.ts"],
      outdir: "./tmp/quality/web",
      target: "bun",
    }),
  ];

  const results = await Promise.all(builds);
  const failures = results.flatMap((result) =>
    result.logs
      .filter((log) => log.level === "error")
      .map((log) => `${log.position?.file ?? "build"}: ${log.message}`),
  );

  if (failures.length > 0 || results.some((result) => !result.success)) {
    throw new Error(failures.join("\n") || "Typecheck build failed");
  }
}

async function main(): Promise<void> {
  const mode = process.argv[2] as QualityMode | undefined;

  if (!mode) {
    throw new Error("Missing quality mode");
  }

  if (mode === "format:check") {
    formatCheck(false);
    return;
  }

  if (mode === "format:write") {
    formatCheck(true);
    return;
  }

  if (mode === "lint") {
    lintCheck();
    return;
  }

  if (mode === "typecheck") {
    await typecheck();
    return;
  }

  throw new Error(`Unknown quality mode: ${mode}`);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});


