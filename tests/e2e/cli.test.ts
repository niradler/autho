import { mkdtempSync, writeFileSync } from "node:fs";
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
    ]) as { username: string; value: string };
    expect(fetched.username).toBe("nirad");
    expect(fetched.value).toBe("ghp_example_secret");

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
      "20",
    ]) as Array<{ eventType: string }>;
    expect(audit.map((event) => event.eventType)).toEqual(
      expect.arrayContaining([
        "vault.initialized",
        "secret.created",
        "otp.generated",
        "lease.created",
        "env.rendered",
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
});
