import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { createConnection } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { expect, test } from "bun:test";

import { VaultService } from "../../packages/core/src/index.ts";

const cwd = join(import.meta.dir, "../..");
const baseEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("AUTHO_")));

function setup() {
  const directory = mkdtempSync(join(tmpdir(), "autho-lifecycle-"));
  const statePath = join(directory, "daemon.json");
  const vaultPath = join(directory, "vault.db");
  const env = { ...baseEnv, AUTHO_HOME: directory, AUTHO_DISABLE_OS_SECRETS: "1" };
  VaultService.initialize(vaultPath, "isolated-lifecycle-password");
  function spawn() {
    return Bun.spawn(["bun", "--no-env-file", "run", "apps/daemon/src/index.ts", "serve", "--vault", vaultPath, "--state-file", statePath], {
      cwd, env, stdout: "pipe", stderr: "pipe",
    });
  }
  async function ready(child: ReturnType<typeof spawn>): Promise<{ pid: number; port: number; token: string }> {
    const deadline = Date.now() + 5000;
    while (Date.now() < deadline) {
      if (existsSync(statePath)) {
        const state = JSON.parse(readFileSync(statePath, "utf8")) as { pid: number; port: number; token: string };
        try {
          if (state.pid === child.pid && (await fetch(`http://127.0.0.1:${state.port}/health`)).ok) return state;
        } catch { /* Wait for readiness. */ }
      }
      await Bun.sleep(25);
    }
    throw new Error("Daemon did not become ready");
  }
  return { ready, spawn, statePath };
}

test("should reject duplicate daemon startup and preserve the active state owner", async () => {
  const fixture = setup();
  const first = fixture.spawn();
  let second: ReturnType<typeof fixture.spawn> | undefined;
  try {
    const initial = await fixture.ready(first);
    second = fixture.spawn();
    const exit = await Promise.race([second.exited, Bun.sleep(2000).then(() => null)]);
    expect(exit).toBe(1);
    const current = JSON.parse(readFileSync(fixture.statePath, "utf8")) as { pid: number };
    expect(current.pid).toBe(initial.pid);
    expect((await fetch(`http://127.0.0.1:${initial.port}/health`)).status).toBe(200);
  } finally {
    second?.kill(); first.kill();
    if (second) await second.exited;
    await first.exited;
  }
});

test("should recover from a crashed daemon's stale state file", async () => {
  const fixture = setup();
  const first = fixture.spawn();
  let replacement: ReturnType<typeof fixture.spawn> | undefined;
  try {
    await fixture.ready(first);
    first.kill("SIGKILL"); await first.exited;
    replacement = fixture.spawn();
    const state = await fixture.ready(replacement);
    expect(state.pid).toBe(replacement.pid);
  } finally {
    first.kill(); replacement?.kill();
    if (replacement) await replacement.exited;
    await first.exited;
  }
});

test("should bound shutdown while an authenticated client leaves its request body unfinished", async () => {
  const fixture = setup();
  const daemon = fixture.spawn();
  let socket: ReturnType<typeof createConnection> | undefined;
  try {
    const state = await fixture.ready(daemon);
    socket = createConnection({ host: "127.0.0.1", port: state.port });
    socket.on("error", () => undefined);
    await new Promise<void>((resolve, reject) => { socket!.once("connect", resolve); socket!.once("error", reject); });
    socket.write(`POST /unlock HTTP/1.1\r\nHost: 127.0.0.1:${state.port}\r\nAuthorization: Bearer ${state.token}\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{`);
    await Bun.sleep(50);
    const response = await fetch(`http://127.0.0.1:${state.port}/shutdown`, {
      method: "POST", headers: { authorization: `Bearer ${state.token}` }, signal: AbortSignal.timeout(2000),
    });
    expect(response.ok).toBe(true);
    const exit = await Promise.race([daemon.exited, Bun.sleep(6500).then(() => null)]);
    expect(exit).toBe(0);
  } finally {
    socket?.destroy(); daemon.kill(); await daemon.exited;
  }
}, 12_000);
