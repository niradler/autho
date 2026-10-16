import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { VaultService, type VaultSession } from "../../packages/core/src/index.ts";
import { Clipboard, type CommandRunner } from "../../apps/cli/src/clipboard.ts";
import { App } from "../../apps/cli/src/tui.tsx";
import { render } from "./setup.ts";

const PASSWORD = "correct-horse-battery";
const SECRET = "Sup3r-S3cret-Value!";

type Harness = Awaited<ReturnType<typeof render>>;

let dir: string;
let vaultPath: string;
let copies: string[];
let quits: number;
let t: Harness | null = null;
let sink: { current: VaultSession | null };

function fakeClipboard(): Clipboard {
  const runner: CommandRunner = async (cmd, _args, input) => {
    if (cmd === "xclip") copies.push(input);
    return { code: 0, stdout: copies.at(-1) ?? "" };
  };
  return new Clipboard({ platform: "linux", env: { DISPLAY: ":0" }, runner });
}

async function frameContaining(text: string, timeoutMs = 3000): Promise<string> {
  const deadline = Date.now() + timeoutMs;
  let frame = "";
  while (Date.now() < deadline) {
    await t!.renderOnce();
    frame = t!.captureCharFrame();
    if (frame.includes(text)) return frame;
    await Bun.sleep(20);
  }
  throw new Error(`Timed out waiting for "${text}". Last frame:\n${frame}`);
}

async function settle(): Promise<string> {
  await Bun.sleep(30);
  await t!.renderOnce();
  return t!.captureCharFrame();
}

async function renderUnlocked(width = 120): Promise<void> {
  t = await render(
    <App vaultPath={vaultPath} clipboard={fakeClipboard()} revealMs={30_000} clipboardClearMs={30_000} idleLockMs={0} onQuit={() => { quits += 1; }} sessionSink={sink} />,
    { width, height: 30, exitOnCtrlC: false },
  );
  await frameContaining("Unlock your vault");
  await t.mockInput.typeText(PASSWORD);
  t.mockInput.pressEnter();
  await frameContaining("github");
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "autho-tui-"));
  vaultPath = join(dir, "vault.db");
  copies = [];
  quits = 0;
  sink = { current: null };
  VaultService.initialize(vaultPath, PASSWORD);
  const session = VaultService.unlock(vaultPath, PASSWORD);
  session.addSecret({ name: "github", type: "password", username: "octocat", value: SECRET, metadata: { url: "https://github.com" } });
  session.close();
});

afterEach(() => {
  t?.renderer.destroy();
  t = null;
  // Windows keeps the vault file locked while the session's DB handle is open.
  sink.current?.close();
  rmSync(dir, { recursive: true, force: true });
});

describe("TUI", () => {
  test("password input stays masked, including pasted text", async () => {
    t = await render(
      <App vaultPath={vaultPath} clipboard={fakeClipboard()} revealMs={30_000} clipboardClearMs={30_000} idleLockMs={0} onQuit={() => {}} sessionSink={sink} />,
      { width: 100, height: 20, exitOnCtrlC: false },
    );
    await frameContaining("Unlock your vault");
    await t.mockInput.typeText("abc");
    await t.mockInput.pasteBracketedText("pasted-part");
    const frame = await settle();
    expect(frame).not.toContain("abc");
    expect(frame).not.toContain("pasted-part");
    expect(frame).toContain("•".repeat("abcpasted-part".length));
  });

  test("the vault view never shows the secret until revealed", async () => {
    await renderUnlocked();
    const frame = await frameContaining("octocat");
    expect(frame).not.toContain(SECRET);
    t!.mockInput.pressKey("s");
    expect(await frameContaining(SECRET)).toContain(SECRET);
  });

  test("copies the password and the username", async () => {
    await renderUnlocked();
    t!.mockInput.pressKey("c");
    await frameContaining("Password copied");
    t!.mockInput.pressKey("u");
    await frameContaining("Username copied");
    expect(copies).toEqual([SECRET, "octocat"]);
  });

  test("first ctrl+c copies instead of quitting; a second one quits", async () => {
    await renderUnlocked();
    t!.mockInput.pressCtrlC();
    await frameContaining("ctrl+c again to quit");
    expect(copies).toEqual([SECRET]);
    expect(quits).toBe(0);
    t!.mockInput.pressCtrlC();
    await settle();
    expect(quits).toBe(1);
  });

  test("ctrl+c copies a mouse selection of the revealed value", async () => {
    await renderUnlocked();
    t!.mockInput.pressKey("s");
    const frame = await frameContaining(SECRET);
    const lines = frame.split("\n");
    const y = lines.findIndex((line) => line.includes(SECRET));
    const x = lines[y]!.indexOf(SECRET);
    await t!.mockMouse.drag(x, y, x + SECRET.length - 1, y);
    await settle();
    t!.mockInput.pressCtrlC();
    await frameContaining("Selection copied");
    expect(copies).toEqual([SECRET]);
    expect(quits).toBe(0);
  });

  test("editing never puts the stored value on screen", async () => {
    await renderUnlocked();
    t!.mockInput.pressKey("e");
    const frame = await frameContaining("leave empty to keep the current value");
    expect(frame).toContain("octocat");
    expect(frame).not.toContain(SECRET);
  });

  test("ctrl+k opens the command palette and runs a command", async () => {
    await renderUnlocked();
    t!.mockInput.pressKey("k", { ctrl: true });
    await frameContaining("Commands");
    await settle();
    await t!.mockInput.typeText("lock vault");
    t!.mockInput.pressEnter();
    await frameContaining("Unlock your vault");
  });
});
