import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";

const repoRoot = process.cwd();
const hookDir = join(repoRoot, ".githooks");
const hookPath = join(hookDir, "pre-commit");

mkdirSync(hookDir, { recursive: true });

if (existsSync(hookPath)) {
  chmodSync(hookPath, 0o755);
}

execFileSync(
  "git",
  ["-c", `safe.directory=${repoRoot.replace(/\\/g, "/")}`, "-C", repoRoot, "config", "core.hooksPath", ".githooks"],
  {
    cwd: repoRoot,
    stdio: "inherit",
  },
);
console.log("Configured git hooks at .githooks");
