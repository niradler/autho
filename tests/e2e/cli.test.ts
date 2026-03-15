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

const repoRoot = join(import.meta.dir, "..", "..");

function runCli(args: string[]) {
  const result = Bun.spawnSync({
    cmd: ["bun", "run", "./apps/cli/src/index.ts", ...args],
    cwd: repoRoot,
    stderr: "pipe",
    stdout: "pipe",
  });

  return {
    exitCode: result.exitCode,
    stderr: result.stderr.toString("utf8"),
    stdout: result.stdout.toString("utf8"),
  };
}

function runCliJson(args: string[]) {
  const result = runCli([...args, "--json"]);
  expect(result.exitCode).toBe(0);

  return JSON.parse(result.stdout) as unknown;
}

describe("autho rewrite CLI", () => {
  test("covers init, secret CRUD, otp, lease, env, exec, audit, and revoke flows", () => {
    const tempRoot = mkdtempSync(join(tmpdir(), "autho-e2e-"));
    const vaultPath = join(tempRoot, ".autho", "vault.db");
    const projectFile = join(tempRoot, "project.json");
    const password = "correct horse battery staple";

    writeFileSync(
      projectFile,
      JSON.stringify(
        {
          env: {
            AUTHO_PASSWORD: "github",
            AUTHO_NOTE: "memo",
          },
        },
        null,
        2,
      ),
    );

    expect(
      runCli(["init", "--vault", vaultPath, "--password", password]).exitCode,
    ).toBe(0);

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
      "--map",
      "AUTHO_PASSWORD=github",
      "--",
      "bun",
      "-e",
      "process.stdout.write(process.env.AUTHO_PASSWORD ?? '')",
    ]);
    expect(execResult.exitCode).toBe(0);
    expect(execResult.stdout).toBe("ghp_example_secret");

    expect(
      runCli([
        "lease",
        "revoke",
        "--vault",
        vaultPath,
        "--password",
        password,
        "--lease",
        lease.id,
      ]).exitCode,
    ).toBe(0);

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
});
