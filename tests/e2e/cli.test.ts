import { createHmac } from "node:crypto";
import {
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "bun:test";
import { deletePin, storePinHash } from "../../packages/core/src/os-secrets.ts";
import { VaultService } from "../../packages/core/src/index.ts";

const repoRoot = join(import.meta.dir, "..", "..");
const testAuthoHome = mkdtempSync(join(tmpdir(), "autho-home-"));

function runCli(args: string[], env?: Record<string, string>) {
  const result = Bun.spawnSync({
    cmd: ["bun", "run", "./apps/cli/src/index.ts", ...args],
    cwd: repoRoot,
    env: {
      ...process.env,
      AUTHO_HOME: testAuthoHome,
      AUTHO_DISABLE_OS_SECRETS: "1",
      ...(env ?? {}),
    },
    stderr: "pipe",
    stdout: "pipe",
  });

  return {
    exitCode: result.exitCode,
    stderr: result.stderr.toString("utf8"),
    stdout: result.stdout.toString("utf8"),
  };
}

async function runCliInteractive(args: string[], input: string, env?: Record<string, string>) {
  const processRef = Bun.spawn({
    cmd: ["bun", "run", "./apps/cli/src/index.ts", ...args],
    cwd: repoRoot,
    env: {
      ...process.env,
      AUTHO_HOME: testAuthoHome,
      AUTHO_DISABLE_OS_SECRETS: "1",
      ...(env ?? {}),
    },
    stdin: "pipe",
    stderr: "pipe",
    stdout: "pipe",
  });

  processRef.stdin.write(input);
  processRef.stdin.end();
  const exitCode = await processRef.exited;

  return {
    exitCode,
    stderr: await new Response(processRef.stderr).text(),
    stdout: await new Response(processRef.stdout).text(),
  };
}

function runCliJson(args: string[], env?: Record<string, string>) {
  const result = runCli([...args, "--json"], env);
  expect(result.exitCode).toBe(0);

  return JSON.parse(result.stdout) as unknown;
}

async function waitFor(check: () => boolean | Promise<boolean>, timeoutMs = 5000): Promise<void> {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    if (await check()) {
      return;
    }
    await Bun.sleep(100);
  }
  throw new Error("Timed out waiting for condition");
}

function cookieHeader(setCookie: string | null): string {
  return (setCookie ?? "").split(";")[0] ?? "";
}

// Runs CLI without disabling OS secrets (needed for PIN tests)
function runCliOsSecrets(args: string[], env?: Record<string, string>) {
  const result = Bun.spawnSync({
    cmd: ["bun", "run", "./apps/cli/src/index.ts", ...args],
    cwd: repoRoot,
    env: {
      ...process.env,
      AUTHO_HOME: testAuthoHome,
      ...(env ?? {}),
    },
    stderr: "pipe",
    stdout: "pipe",
  });

  return {
    exitCode: result.exitCode,
    stderr: result.stderr.toString("utf8"),
    stdout: result.stdout.toString("utf8"),
  };
}

function runCliOsSecretsJson(args: string[], env?: Record<string, string>) {
  const result = runCliOsSecrets([...args, "--json"], env);
  expect(result.exitCode).toBe(0);
  return JSON.parse(result.stdout) as unknown;
}

// Minimal RFC 6238 TOTP code generator for tests (mirrors crypto/src/index.ts)
function computeTotp(base32Secret: string): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  const keyBytes: number[] = [];
  for (const char of base32Secret.toUpperCase()) {
    const idx = alphabet.indexOf(char);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      keyBytes.push((value >> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  const key = Buffer.from(keyBytes);
  const counter = Math.floor(Date.now() / 30_000);
  const message = Buffer.alloc(8);
  let cursor = counter;
  for (let index = 7; index >= 0; index -= 1) {
    message[index] = cursor & 0xff;
    cursor >>= 8;
  }

  const hash = createHmac("sha1", key).update(message).digest();
  const offset = hash[hash.length - 1] & 0x0f;
  const binary =
    ((hash[offset] & 0x7f) << 24) |
    ((hash[offset + 1] & 0xff) << 16) |
    ((hash[offset + 2] & 0xff) << 8) |
    (hash[offset + 3] & 0xff);
  return String(binary % 1_000_000).padStart(6, "0");
}

describe("autho rewrite CLI", () => {
  test("covers init, project config, status, secret CRUD, otp, lease, env, exec, audit, and revoke flows", { timeout: 15000 }, () => {
    const tempRoot = mkdtempSync(join(tmpdir(), "autho-e2e-"));
    const vaultPath = join(tempRoot, ".autho", "vault.db");
    const projectFile = join(tempRoot, ".autho", "project.json");
    const password = "correct horse battery staple";

    expect(runCli(["init", "--vault", vaultPath, "--password", password]).exitCode).toBe(0);

    const projectInit = runCliJson([
      "project",
      "init",
      "--output",
      projectFile,
      "--map",
      "AUTHO_PASSWORD=github",
      "--map",
      "AUTHO_NOTE=memo",
      "--force",
    ]) as { mappingCount: number; outputPath: string };
    expect(projectInit.mappingCount).toBe(2);
    expect(projectInit.outputPath).toBe(projectFile);

    const initialStatus = runCliJson([
      "status",
      "--vault",
      vaultPath,
      "--project-file",
      projectFile,
    ]) as { initialized: boolean; projectMappings: string[]; unlocked: boolean };
    expect(initialStatus.initialized).toBe(true);
    expect(initialStatus.unlocked).toBe(false);
    expect(initialStatus.projectMappings).toEqual(["AUTHO_PASSWORD", "AUTHO_NOTE"]);

    const passwordSecret = runCliJson([
      "secrets",
      "add",
      "--vault",
      vaultPath,
      "--password",
      password,
      "--name",
      "github",
      "--type",
      "password",
      "--value",
      "ghp_example_secret",
      "--username",
      "nirad",
      "--url",
      "https://github.com",
    ]) as { id: string; name: string };

    runCliJson([
      "secrets",
      "add",
      "--vault",
      vaultPath,
      "--password",
      password,
      "--name",
      "memo",
      "--type",
      "note",
      "--value",
      "ship the rewrite",
      "--description",
      "rewrite notes",
    ]);

    runCliJson([
      "secrets",
      "add",
      "--vault",
      vaultPath,
      "--password",
      password,
      "--name",
      "totp",
      "--type",
      "otp",
      "--value",
      "JBSWY3DPEHPK3PXP",
      "--digits",
      "6",
      "--algorithm",
      "SHA1",
    ]);

    const unlockedStatus = runCliJson([
      "status",
      "--vault",
      vaultPath,
      "--password",
      password,
      "--project-file",
      projectFile,
    ]) as {
      activeLeaseCount: number;
      initialized: boolean;
      projectMappings: string[];
      secretCount: number;
      unlocked: boolean;
    };
    expect(unlockedStatus.initialized).toBe(true);
    expect(unlockedStatus.unlocked).toBe(true);
    expect(unlockedStatus.secretCount).toBe(3);
    expect(unlockedStatus.activeLeaseCount).toBe(0);
    expect(unlockedStatus.projectMappings).toEqual(["AUTHO_PASSWORD", "AUTHO_NOTE"]);

    const listed = runCliJson([
      "secrets",
      "list",
      "--vault",
      vaultPath,
      "--password",
      password,
    ]) as Array<{ name: string; value?: string }>;
    expect(listed).toHaveLength(3);
    expect(listed.some((secret) => "value" in secret)).toBe(false);

    const fetched = runCliJson([
      "secrets",
      "get",
      "--vault",
      vaultPath,
      "--password",
      password,
      "--ref",
      "github",
    ]) as { metadata: { url: string }; username: string; value: string };
    expect(fetched.username).toBe("nirad");
    expect(fetched.value).toBe("ghp_example_secret");
    expect(fetched.metadata.url).toBe("https://github.com");

    const otp = runCliJson([
      "otp",
      "code",
      "--vault",
      vaultPath,
      "--password",
      password,
      "--ref",
      "totp",
    ]) as { code: string };
    expect(otp.code).toHaveLength(6);

    const lease = runCliJson([
      "lease",
      "create",
      "--vault",
      vaultPath,
      "--password",
      password,
      "--name",
      "agent-build",
      "--ttl",
      "120",
      "--secret",
      "github",
      "--secret",
      "memo",
    ]) as { id: string };

    const envRender = runCliJson([
      "env",
      "render",
      "--vault",
      vaultPath,
      "--password",
      password,
      "--lease",
      lease.id,
      "--project-file",
      projectFile,
    ]) as Record<string, string>;
    expect(envRender.AUTHO_PASSWORD).toBe("ghp_example_secret");
    expect(envRender.AUTHO_NOTE).toBe("ship the rewrite");

    const envFile = join(tempRoot, ".env.autho");
    const syncResult = runCliJson([
      "env",
      "sync",
      "--vault",
      vaultPath,
      "--password",
      password,
      "--lease",
      lease.id,
      "--project-file",
      projectFile,
      "--output",
      envFile,
      "--ttl",
      "60",
    ]) as { outputPath: string; varCount: number };
    expect(syncResult.outputPath).toBe(envFile);
    expect(syncResult.varCount).toBe(2);
    expect(readFileSync(envFile, "utf8")).toContain('AUTHO_PASSWORD="ghp_example_secret"');

    const execResult = runCli([
      "exec",
      "--vault",
      vaultPath,
      "--password",
      password,
      "--lease",
      lease.id,
      "--project-file",
      projectFile,
      "--",
      "bun",
      "-e",
      "process.stdout.write(process.env.AUTHO_PASSWORD + ':' + process.env.AUTHO_NOTE)",
    ]);
    expect(execResult.exitCode).toBe(0);
    expect(execResult.stdout).toBe("ghp_example_secret:ship the rewrite");

    expect(runCli(["lease", "revoke", "--vault", vaultPath, "--password", password, "--lease", lease.id]).exitCode).toBe(0);

    const rejected = runCli([
      "env",
      "render",
      "--vault",
      vaultPath,
      "--password",
      password,
      "--lease",
      lease.id,
      "--map",
      "AUTHO_PASSWORD=github",
    ]);
    expect(rejected.exitCode).toBe(1);
    expect(rejected.stderr).toContain("Lease revoked");

    const audit = runCliJson([
      "audit",
      "list",
      "--vault",
      vaultPath,
      "--password",
      password,
      "--limit",
      "30",
    ]) as Array<{ eventType: string }>;
    expect(audit.map((event) => event.eventType)).toEqual(
      expect.arrayContaining([
        "vault.initialized",
        "secret.created",
        "otp.generated",
        "lease.created",
        "env.rendered",
        "env.synced",
        "exec.run",
        "lease.revoked",
      ]),
    );

    const remove = runCliJson([
      "secrets",
      "rm",
      "--vault",
      vaultPath,
      "--password",
      password,
      "--ref",
      passwordSecret.id,
    ]) as { name: string };
    expect(remove.name).toBe("github");
  });

  test("covers interactive prompt mode for create and list flows", async () => {
    const tempRoot = mkdtempSync(join(tmpdir(), "autho-prompt-"));
    const vaultPath = join(tempRoot, ".autho", "vault.db");
    const password = "correct horse battery staple";

    expect(runCli(["init", "--vault", vaultPath, "--password", password]).exitCode).toBe(0);

    const createResult = await runCliInteractive(
      ["prompt", "--vault", vaultPath],
      [
        "create",
        "prompt-secret",
        "note",
        "created from prompt",
        "prompt description",
      ].join("\n") + "\n",
      { AUTHO_MASTER_PASSWORD: password },
    );
    expect(createResult.exitCode).toBe(0);

    const createdSecret = runCliJson([
      "secrets",
      "get",
      "--vault",
      vaultPath,
      "--password",
      password,
      "--ref",
      "prompt-secret",
    ]) as { value: string };
    expect(createdSecret.value).toBe("created from prompt");

    const listResult = await runCliInteractive(
      ["--vault", vaultPath],
      "list\n",
      { AUTHO_MASTER_PASSWORD: password },
    );
    expect(listResult.exitCode).toBe(0);
    expect(listResult.stdout).toContain("prompt-secret");
  });

  test("covers legacy import and secure file or folder encryption flows", () => {
    const tempRoot = mkdtempSync(join(tmpdir(), "autho-artifacts-"));
    const vaultPath = join(tempRoot, ".autho", "vault.db");
    const password = "correct horse battery staple";
    const legacyFile = join(tempRoot, "legacy.json");
    const plainFile = join(tempRoot, "sample.txt");
    const encryptedFile = join(tempRoot, "sample.txt.autho");
    const decryptedFile = join(tempRoot, "sample-copy.txt");
    const sourceFolder = join(tempRoot, "folder");
    const restoredFolder = join(tempRoot, "restored-folder");
    const encryptedFolder = join(tempRoot, "folder.autho-folder");

    writeFileSync(
      legacyFile,
      JSON.stringify(
        [
          {
            description: "GitHub access token",
            name: "imported-password",
            secret: "ghp_imported",
            type: "password",
            url: "https://github.com",
            username: "octocat",
          },
          {
            description: "Imported note",
            name: "imported-note",
            secret: "note body",
            type: "note",
          },
          {
            algorithm: "SHA1",
            digits: 6,
            name: "imported-otp",
            secret: "JBSWY3DPEHPK3PXP",
            type: "otp",
            username: "otp-user",
          },
        ],
        null,
        2,
      ),
    );
    writeFileSync(plainFile, "hello secure world", "utf8");
    mkdirSync(join(sourceFolder, "nested"), { recursive: true });
    writeFileSync(join(sourceFolder, "a.txt"), "alpha", "utf8");
    writeFileSync(join(sourceFolder, "nested", "b.txt"), "beta", "utf8");

    expect(runCli(["init", "--vault", vaultPath, "--password", password]).exitCode).toBe(0);

    const imported = runCliJson([
      "import",
      "legacy",
      "--vault",
      vaultPath,
      "--password",
      password,
      "--file",
      legacyFile,
      "--skip-existing",
    ]) as { imported: number; skipped: number };
    expect(imported.imported).toBe(3);
    expect(imported.skipped).toBe(0);

    const importedSecret = runCliJson([
      "secrets",
      "get",
      "--vault",
      vaultPath,
      "--password",
      password,
      "--ref",
      "imported-password",
    ]) as { metadata: { description: string; url: string }; username: string; value: string };
    expect(importedSecret.username).toBe("octocat");
    expect(importedSecret.value).toBe("ghp_imported");
    expect(importedSecret.metadata.description).toBe("GitHub access token");
    expect(importedSecret.metadata.url).toBe("https://github.com");

    const fileEncrypt = runCliJson([
      "file",
      "encrypt",
      "--vault",
      vaultPath,
      "--password",
      password,
      "--input",
      plainFile,
      "--output",
      encryptedFile,
    ]) as { outputPath: string };
    expect(fileEncrypt.outputPath).toBe(encryptedFile);
    expect(existsSync(encryptedFile)).toBe(true);
    expect(readFileSync(encryptedFile, "utf8")).not.toContain("hello secure world");

    const fileDecrypt = runCliJson([
      "file",
      "decrypt",
      "--vault",
      vaultPath,
      "--password",
      password,
      "--input",
      encryptedFile,
      "--output",
      decryptedFile,
    ]) as { outputPath: string };
    expect(fileDecrypt.outputPath).toBe(decryptedFile);
    expect(readFileSync(decryptedFile, "utf8")).toBe("hello secure world");

    const folderEncrypt = runCliJson([
      "files",
      "encrypt",
      "--vault",
      vaultPath,
      "--password",
      password,
      "--input",
      sourceFolder,
      "--output",
      encryptedFolder,
    ]) as { fileCount: number; outputPath: string };
    expect(folderEncrypt.fileCount).toBe(2);
    expect(folderEncrypt.outputPath).toBe(encryptedFolder);

    const folderDecrypt = runCliJson([
      "files",
      "decrypt",
      "--vault",
      vaultPath,
      "--password",
      password,
      "--input",
      encryptedFolder,
      "--output",
      restoredFolder,
    ]) as { fileCount: number; outputPath: string };
    expect(folderDecrypt.fileCount).toBe(2);
    expect(readFileSync(join(restoredFolder, "a.txt"), "utf8")).toBe("alpha");
    expect(readFileSync(join(restoredFolder, "nested", "b.txt"), "utf8")).toBe("beta");

    const audit = runCliJson([
      "audit",
      "list",
      "--vault",
      vaultPath,
      "--password",
      password,
      "--limit",
      "30",
    ]) as Array<{ eventType: string }>;
    expect(audit.map((event) => event.eventType)).toEqual(
      expect.arrayContaining([
        "import.legacy",
        "file.encrypted",
        "file.decrypted",
        "folder.encrypted",
        "folder.decrypted",
      ]),
    );
  });

  test("covers daemon-backed unlock, env render, exec, lock, and stop flows", async () => {
    const tempRoot = mkdtempSync(join(tmpdir(), "autho-daemon-"));
    const vaultPath = join(tempRoot, ".autho", "vault.db");
    const projectFile = join(tempRoot, ".autho", "project.json");
    const stateFile = join(tempRoot, ".autho", "daemon.json");
    const password = "correct horse battery staple";

    expect(runCli(["init", "--vault", vaultPath, "--password", password]).exitCode).toBe(0);
    runCliJson(["project", "init", "--output", projectFile, "--map", "AUTHO_PASSWORD=github", "--map", "AUTHO_NOTE=memo", "--force"]);
    runCliJson(["secrets", "add", "--vault", vaultPath, "--password", password, "--name", "github", "--type", "password", "--value", "ghp_example_secret"]);
    runCliJson(["secrets", "add", "--vault", vaultPath, "--password", password, "--name", "memo", "--type", "note", "--value", "ship the rewrite"]);

    const daemon = Bun.spawn({
      cmd: ["bun", "run", "./apps/daemon/src/index.ts", "serve", "--vault", vaultPath, "--state-file", stateFile, "--port", "0"],
      cwd: repoRoot,
      stderr: "pipe",
      stdout: "pipe",
    });

    try {
      await waitFor(() => existsSync(stateFile));
      await waitFor(() => runCli(["daemon", "status", "--state-file", stateFile]).exitCode === 0);

      const daemonStatus = runCliJson(["daemon", "status", "--state-file", stateFile]) as { activeSessions: number; status: { initialized: boolean } };
      expect(daemonStatus.activeSessions).toBe(0);
      expect(daemonStatus.status.initialized).toBe(true);

      const unlocked = runCliJson(["daemon", "unlock", "--state-file", stateFile, "--password", password, "--ttl", "120"]) as { expiresAt: string; sessionId: string };
      expect(unlocked.sessionId.length).toBeGreaterThan(10);
      expect(unlocked.expiresAt).toContain("T");

      const envRender = runCliJson(["daemon", "env", "render", "--state-file", stateFile, "--session", unlocked.sessionId, "--project-file", projectFile]) as Record<string, string>;
      expect(envRender.AUTHO_PASSWORD).toBe("ghp_example_secret");
      expect(envRender.AUTHO_NOTE).toBe("ship the rewrite");

      const execResult = runCli([
        "daemon",
        "exec",
        "--state-file",
        stateFile,
        "--session",
        unlocked.sessionId,
        "--project-file",
        projectFile,
        "--",
        "bun",
        "-e",
        "process.stdout.write(process.env.AUTHO_PASSWORD + ':' + process.env.AUTHO_NOTE)",
      ]);
      expect(execResult.exitCode).toBe(0);
      expect(execResult.stdout).toBe("ghp_example_secret:ship the rewrite");

      expect(runCli(["daemon", "lock", "--state-file", stateFile, "--session", unlocked.sessionId]).exitCode).toBe(0);

      const lockedEnv = runCli(["daemon", "env", "render", "--state-file", stateFile, "--session", unlocked.sessionId, "--project-file", projectFile]);
      expect(lockedEnv.exitCode).toBe(1);
      expect(lockedEnv.stderr).toContain("Unknown daemon session");

      expect(runCli(["daemon", "stop", "--state-file", stateFile]).exitCode).toBe(0);
      await waitFor(() => !existsSync(stateFile));
    } finally {
      daemon.kill();
      await daemon.exited;
    }
  });

  test("covers local web unlock and secret api flows", async () => {
    const tempRoot = mkdtempSync(join(tmpdir(), "autho-web-"));
    const vaultPath = join(tempRoot, ".autho", "vault.db");
    const password = "correct horse battery staple";
    const port = 18000 + Math.floor(Math.random() * 1000);

    expect(runCli(["init", "--vault", vaultPath, "--password", password]).exitCode).toBe(0);
    runCliJson(["secrets", "add", "--vault", vaultPath, "--password", password, "--name", "github", "--type", "password", "--value", "ghp_example_secret"]);

    const web = Bun.spawn({
      cmd: ["bun", "run", "./apps/web/src/index.ts", "serve", "--vault", vaultPath, "--port", String(port)],
      cwd: repoRoot,
      stderr: "pipe",
      stdout: "pipe",
    });

    try {
      await waitFor(async () => {
        try {
          const response = await fetch(`http://127.0.0.1:${port}/health`);
          return response.ok;
        } catch {
          return false;
        }
      });

      const pageResponse = await fetch(`http://127.0.0.1:${port}/`);
      expect(pageResponse.status).toBe(200);
      expect(await pageResponse.text()).toContain("Autho Local Web");

      const unlockResponse = await fetch(`http://127.0.0.1:${port}/api/session/unlock`, {
        body: JSON.stringify({ password }),
        headers: { "content-type": "application/json" },
        method: "POST",
      });
      expect(unlockResponse.status).toBe(200);
      const cookie = cookieHeader(unlockResponse.headers.get("set-cookie"));
      expect(cookie).toContain("autho_session=");

      const statusResponse = await fetch(`http://127.0.0.1:${port}/api/status`, {
        headers: { cookie },
      });
      expect(statusResponse.status).toBe(200);
      const statusBody = (await statusResponse.json()) as { secretCount: number };
      expect(statusBody.secretCount).toBe(1);

      const listResponse = await fetch(`http://127.0.0.1:${port}/api/secrets`, {
        headers: { cookie },
      });
      expect(listResponse.status).toBe(200);
      const listed = (await listResponse.json()) as { data: Array<{ name: string }> };
      expect(listed.data[0].name).toBe("github");

      const createResponse = await fetch(`http://127.0.0.1:${port}/api/secrets`, {
        body: JSON.stringify({ name: "memo", type: "note", value: "web note" }),
        headers: { "content-type": "application/json", cookie },
        method: "POST",
      });
      expect(createResponse.status).toBe(201);

      const getResponse = await fetch(`http://127.0.0.1:${port}/api/secrets/memo`, {
        headers: { cookie },
      });
      expect(getResponse.status).toBe(200);
      const secret = (await getResponse.json()) as { data: { value: string } };
      expect(secret.data.value).toBe("web note");

      const deleteResponse = await fetch(`http://127.0.0.1:${port}/api/secrets/memo`, {
        headers: { cookie },
        method: "DELETE",
      });
      expect(deleteResponse.status).toBe(200);

      const lockResponse = await fetch(`http://127.0.0.1:${port}/api/session/lock`, {
        headers: { cookie },
        method: "POST",
      });
      expect(lockResponse.status).toBe(200);

      const unauthorized = await fetch(`http://127.0.0.1:${port}/api/secrets`, {
        headers: { cookie },
      });
      expect(unauthorized.status).toBe(401);
    } finally {
      web.kill();
      await web.exited;
    }
  });
});

describe("autho security features (PIN, TOTP, recovery file)", () => {
  test("TOTP vault unlock: enable, verify, wrong code fails, remove", { timeout: 15000 }, () => {
    const tempRoot = mkdtempSync(join(tmpdir(), "autho-totp-"));
    const vaultPath = join(tempRoot, ".autho", "vault.db");
    const password = "correct horse battery staple";

    // Init vault (no TTY → wizard is skipped)
    expect(runCli(["init", "--vault", vaultPath, "--password", password]).exitCode).toBe(0);

    // Add a secret so we can verify unlock works
    runCliJson(["secrets", "add", "--vault", vaultPath, "--password", password, "--name", "s1", "--type", "note", "--value", "hello"]);

    // Enable TOTP programmatically (wizard is TTY-only)
    const { secret } = VaultService.setupTotp(vaultPath);
    VaultService.enableTotp(vaultPath, { password }, secret, computeTotp(secret));

    // Unlock with valid TOTP code → succeeds
    const listed = runCliJson([
      "secrets", "list",
      "--vault", vaultPath,
      "--password", password,
      "--totp", computeTotp(secret),
    ]) as Array<{ name: string }>;
    expect(listed.some((s) => s.name === "s1")).toBe(true);

    // Unlock with wrong TOTP code → fails
    const bad = runCli(["secrets", "list", "--vault", vaultPath, "--password", password, "--totp", "000000"]);
    expect(bad.exitCode).toBe(1);
    expect(bad.stderr).toContain("Invalid or missing TOTP code");

    // Unlock without providing TOTP → fails
    const missing = runCli(["secrets", "list", "--vault", vaultPath, "--password", password]);
    expect(missing.exitCode).toBe(1);
    expect(missing.stderr).toContain("TOTP is enabled");

    // Remove TOTP
    VaultService.removeTotp(vaultPath, { password, totp: computeTotp(secret) });

    // After removal: unlock without TOTP → succeeds
    const afterRemove = runCliJson([
      "secrets", "list",
      "--vault", vaultPath,
      "--password", password,
    ]) as Array<{ name: string }>;
    expect(afterRemove.some((s) => s.name === "s1")).toBe(true);

    // Audit trail contains TOTP events
    const audit = runCliJson(["audit", "list", "--vault", vaultPath, "--password", password, "--limit", "20"]) as Array<{ eventType: string }>;
    const types = audit.map((e) => e.eventType);
    expect(types).toContain("auth.totp.enabled");
    expect(types).toContain("auth.totp.removed");
  });

  test("recovery file: generate, unlock, revoke, post-revoke unlock fails", { timeout: 20000 }, () => {
    const tempRoot = mkdtempSync(join(tmpdir(), "autho-recovery-"));
    const vaultPath = join(tempRoot, ".autho", "vault.db");
    const recoveryFile = join(tempRoot, "vault.recovery");
    const password = "correct horse battery staple";

    expect(runCli(["init", "--vault", vaultPath, "--password", password]).exitCode).toBe(0);
    runCliJson(["secrets", "add", "--vault", vaultPath, "--password", password, "--name", "secure-note", "--type", "note", "--value", "top-secret"]);

    // Generate recovery file via CLI
    const genResult = runCli([
      "recovery", "generate",
      "--vault", vaultPath,
      "--password", password,
      "--output", recoveryFile,
    ]);
    expect(genResult.exitCode).toBe(0);
    expect(existsSync(recoveryFile)).toBe(true);

    // Recovery file has expected format
    const content = readFileSync(recoveryFile, "utf8");
    expect(content).toContain("AUTHO VAULT RECOVERY FILE");
    expect(content).toContain("RECOVERY TOKEN:");
    expect(content).toContain("autho unlock --recovery-file");

    // Unlock with recovery file → succeeds (bypasses password / TOTP / PIN)
    const unlockResult = runCliJson([
      "unlock",
      "--vault", vaultPath,
      "--recovery-file", recoveryFile,
    ]) as { unlocked: boolean };
    expect(unlockResult.unlocked).toBe(true);

    // Revoke recovery
    const revokeResult = runCli([
      "recovery", "revoke",
      "--vault", vaultPath,
      "--password", password,
      "--json",
    ]);
    expect(revokeResult.exitCode).toBe(0);
    expect(JSON.parse(revokeResult.stdout)).toMatchObject({ revoked: true });

    // Unlock after revoke → fails
    const badUnlock = runCli([
      "unlock",
      "--vault", vaultPath,
      "--recovery-file", recoveryFile,
    ]);
    expect(badUnlock.exitCode).toBe(1);

    // Audit trail
    const audit = runCliJson(["audit", "list", "--vault", vaultPath, "--password", password, "--limit", "20"]) as Array<{ eventType: string }>;
    const types = audit.map((e) => e.eventType);
    expect(types).toContain("auth.recovery.generated");
    expect(types).toContain("auth.recovery.revoked");
  });

  test("recovery file: unlock bypasses TOTP when recovery file is present", { timeout: 15000 }, () => {
    const tempRoot = mkdtempSync(join(tmpdir(), "autho-recovery-totp-"));
    const vaultPath = join(tempRoot, ".autho", "vault.db");
    const recoveryFile = join(tempRoot, "vault.recovery");
    const password = "correct horse battery staple";

    expect(runCli(["init", "--vault", vaultPath, "--password", password]).exitCode).toBe(0);

    // Enable TOTP
    const { secret } = VaultService.setupTotp(vaultPath);
    VaultService.enableTotp(vaultPath, { password }, secret, computeTotp(secret));

    // Generate recovery file (requires TOTP now that it's enabled)
    const genResult = runCli([
      "recovery", "generate",
      "--vault", vaultPath,
      "--password", password,
      "--totp", computeTotp(secret),
      "--output", recoveryFile,
    ]);
    expect(genResult.exitCode).toBe(0);

    // Unlock with recovery file — no TOTP needed
    const unlockResult = runCliJson([
      "unlock",
      "--vault", vaultPath,
      "--recovery-file", recoveryFile,
    ]) as { unlocked: boolean };
    expect(unlockResult.unlocked).toBe(true);
  });

  test("PIN vault protection: set, verify, wrong PIN fails, remove", { timeout: 15000 }, async () => {
    const tempRoot = mkdtempSync(join(tmpdir(), "autho-pin-"));
    const vaultPath = join(tempRoot, ".autho", "vault.db");
    const password = "correct horse battery staple";
    const pin = "4567";

    // Init vault (OS secrets enabled — no AUTHO_DISABLE_OS_SECRETS override)
    expect(runCliOsSecrets(["init", "--vault", vaultPath, "--password", password]).exitCode).toBe(0);

    // Store PIN directly (wizard is TTY-only)
    const stored = await storePinHash(vaultPath, pin);
    if (!stored) {
      // OS secret store unavailable in this environment — skip PIN assertions
      console.log("Skipping PIN test: OS secret store unavailable");
      return;
    }

    // Unlock with correct PIN via CLI
    const listed = runCliOsSecretsJson([
      "secrets", "list",
      "--vault", vaultPath,
      "--password", password,
      "--pin", pin,
    ]) as Array<unknown>;
    expect(Array.isArray(listed)).toBe(true);

    // Unlock with wrong PIN → fails
    const bad = runCliOsSecrets([
      "secrets", "list",
      "--vault", vaultPath,
      "--password", password,
      "--pin", "0000",
    ]);
    expect(bad.exitCode).toBe(1);
    expect(bad.stderr).toContain("Wrong PIN");

    // Unlock without --pin while PIN is set → fails
    const missing = runCliOsSecrets([
      "secrets", "list",
      "--vault", vaultPath,
      "--password", password,
    ]);
    expect(missing.exitCode).toBe(1);
    expect(missing.stderr).toContain("PIN is set");

    // Remove PIN
    const deleted = await deletePin(vaultPath);
    expect(deleted).toBe(true);

    // After removal: unlock without PIN → succeeds
    const afterDelete = runCliOsSecretsJson([
      "secrets", "list",
      "--vault", vaultPath,
      "--password", password,
    ]) as Array<unknown>;
    expect(Array.isArray(afterDelete)).toBe(true);
  });

  test("TOTP + recovery together: all factors can coexist", { timeout: 20000 }, () => {
    const tempRoot = mkdtempSync(join(tmpdir(), "autho-full-"));
    const vaultPath = join(tempRoot, ".autho", "vault.db");
    const recoveryFile = join(tempRoot, "vault.recovery");
    const password = "correct horse battery staple";

    expect(runCli(["init", "--vault", vaultPath, "--password", password]).exitCode).toBe(0);
    runCliJson(["secrets", "add", "--vault", vaultPath, "--password", password, "--name", "test-secret", "--type", "note", "--value", "value"]);

    // Enable TOTP
    const { secret } = VaultService.setupTotp(vaultPath);
    VaultService.enableTotp(vaultPath, { password }, secret, computeTotp(secret));

    // Generate recovery file (must pass TOTP since it's enabled)
    expect(runCli([
      "recovery", "generate",
      "--vault", vaultPath,
      "--password", password,
      "--totp", computeTotp(secret),
      "--output", recoveryFile,
    ]).exitCode).toBe(0);

    // Normal unlock (password + TOTP) works
    const withTotp = runCliJson([
      "secrets", "list",
      "--vault", vaultPath,
      "--password", password,
      "--totp", computeTotp(secret),
    ]) as Array<{ name: string }>;
    expect(withTotp.some((s) => s.name === "test-secret")).toBe(true);

    // Recovery file bypass (no password, no TOTP) works
    const withRecovery = runCliJson([
      "unlock",
      "--vault", vaultPath,
      "--recovery-file", recoveryFile,
    ]) as { unlocked: boolean };
    expect(withRecovery.unlocked).toBe(true);

    // Wrong password but correct TOTP → fails
    const badPw = runCli([
      "secrets", "list",
      "--vault", vaultPath,
      "--password", "wrong-password",
      "--totp", computeTotp(secret),
    ]);
    expect(badPw.exitCode).toBe(1);
  });
});
