import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { VaultService, configFilePath, resetConfigCache, type VaultSession } from "../../packages/core/src/index.ts";
import { Clipboard, type CommandRunner } from "../../apps/cli/src/clipboard.ts";
import { App } from "../../apps/cli/src/tui.tsx";
import type { PasskeyRunner } from "../../apps/cli/src/tui/unlock.tsx";
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

async function renderUnlocked(width = 120, revealMs = 30_000): Promise<void> {
  t = await render(
    <App vaultPath={vaultPath} clipboard={fakeClipboard()} revealMs={revealMs} clipboardClearMs={30_000} idleLockMs={0} onQuit={() => { quits += 1; }} sessionSink={sink} />,
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
  rmSync(configFilePath(), { force: true });
  resetConfigCache();
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

  test("ctrl+r in the editor shows the stored value and saves edits to it", async () => {
    await renderUnlocked();
    t!.mockInput.pressKey("e");
    await frameContaining("leave empty to keep the current value");
    t!.mockInput.pressKey("r", { ctrl: true });
    expect(await frameContaining(SECRET)).toContain(SECRET);
    t!.mockInput.pressKey("!");
    await settle();
    t!.mockInput.pressKey("s", { ctrl: true });
    await frameContaining("Saved");
    expect(sink.current!.getSecret("github").value).toBe(`${SECRET}!`);
  });

  test("a value revealed in the editor hides again and is cleared", async () => {
    await renderUnlocked(120, 300);
    t!.mockInput.pressKey("e");
    await frameContaining("leave empty to keep the current value");
    t!.mockInput.pressKey("r", { ctrl: true });
    await frameContaining(SECRET);
    await Bun.sleep(450);
    const frame = await frameContaining("leave empty to keep the current value");
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

  test("ctrl+p unlocks with a registered passkey", async () => {
    const credentialId = randomBytes(16).toString("base64url");
    const prfOutput = randomBytes(32).toString("base64url");
    VaultService.addPasskey(vaultPath, { password: PASSWORD }, { credentialId, label: "key", prfOutput, prfSalt: randomBytes(32).toString("base64url") });
    const requests: unknown[] = [];
    const runner: PasskeyRunner = async (request, { onUrl }) => {
      requests.push(request);
      onUrl("http://localhost:1/token", true);
      await Bun.sleep(50);
      return { credentialId, prfOutput };
    };
    t = await render(
      <App vaultPath={vaultPath} clipboard={fakeClipboard()} revealMs={30_000} clipboardClearMs={30_000} idleLockMs={0} onQuit={() => {}} sessionSink={sink} passkeyRunner={runner} />,
      { width: 120, height: 30, exitOnCtrlC: false },
    );
    await frameContaining("ctrl+p");
    t.mockInput.pressKey("p", { ctrl: true });
    await frameContaining("Waiting for your browser");
    await frameContaining("github");
    expect(requests).toHaveLength(1);
  });
});

describe("Navigation", () => {
  test("the settings shortcut is always in the status bar on a wide terminal", async () => {
    await renderUnlocked(160);
    const frame = await settle();
    expect(frame).toContain("settings");
    expect(frame).toContain("commands");
  });

  test("tab moves into the actions, arrows pick one and enter runs it", async () => {
    await renderUnlocked();
    t!.mockInput.pressTab();
    await frameContaining("choose");
    // copy · reveal · open · edit · delete — four quick presses land on delete.
    t!.mockInput.pressArrow("right");
    t!.mockInput.pressArrow("right");
    t!.mockInput.pressArrow("right");
    t!.mockInput.pressArrow("right");
    await settle();
    t!.mockInput.pressEnter();
    await frameContaining("permanently?");
    t!.mockInput.pressKey("n");
    await settle();
    expect(sink.current!.getSecret("github").name).toBe("github");
  });

  test("esc steps back from the actions to the list", async () => {
    await renderUnlocked();
    t!.mockInput.pressArrow("right");
    await frameContaining("choose");
    t!.mockInput.pressEscape();
    await frameContaining("→/tab");
  });

  test("shift+tab from the list focuses search", async () => {
    await renderUnlocked();
    t!.mockInput.pressTab({ shift: true });
    await frameContaining("filter");
    await t!.mockInput.typeText("zzz");
    await frameContaining('No match for "zzz"');
  });

  test("settings opens on the sidebar; arrows change section until → enters it", async () => {
    await renderUnlocked();
    t!.mockInput.pressKey(",");
    await frameContaining("Vault file");
    t!.mockInput.pressArrow("down");
    await frameContaining("Master password");
    t!.mockInput.pressArrow("right");
    await settle();
    t!.mockInput.pressArrow("left");
    t!.mockInput.pressEscape();
    await frameContaining("github");
  });
});

describe("Settings", () => {
  async function openSettings(): Promise<void> {
    await renderUnlocked();
    t!.mockInput.pressKey(",");
    await frameContaining("Vault file");
  }

  /** Focus starts on the sidebar: ↓ picks the section, → moves into its rows. */
  async function goToSection(name: string): Promise<string> {
    for (let i = 0; i < 5; i += 1) {
      const frame = await settle();
      if (frame.includes(`› ${name}`)) {
        t!.mockInput.pressArrow("right");
        return settle();
      }
      t!.mockInput.pressArrow("down");
    }
    throw new Error(`Section ${name} not reached`);
  }

  test("shows where the vault lives", async () => {
    await openSettings();
    const frame = await settle();
    expect(frame).toContain("Config file");
    expect(frame).toContain("vault.db");
    t!.mockInput.pressEscape();
    await frameContaining("github");
  });

  test("changing the reveal timeout saves it to config.json", async () => {
    await openSettings();
    await goToSection("Behaviour");
    t!.mockInput.pressEnter();
    await frameContaining("empty resets to 30");
    t!.mockInput.pressBackspace();
    t!.mockInput.pressBackspace();
    await t!.mockInput.typeText("45");
    t!.mockInput.pressEnter();
    await frameContaining("Reveal timeout: 45s");
    expect(JSON.parse(readFileSync(configFilePath(), "utf8")).revealSeconds).toBe(45);
  });

  test("an out-of-range value is refused and nothing is saved", async () => {
    await openSettings();
    await goToSection("Behaviour");
    t!.mockInput.pressEnter();
    await frameContaining("empty resets to 30");
    t!.mockInput.pressBackspace();
    t!.mockInput.pressBackspace();
    await t!.mockInput.typeText("1");
    t!.mockInput.pressEnter();
    await frameContaining("✗");
    expect(() => readFileSync(configFilePath(), "utf8")).toThrow();
  });

  test("changing the master password asks for the current one first", async () => {
    const next = "a-brand-new-passphrase";
    await openSettings();
    await goToSection("Security");
    t!.mockInput.pressEnter();
    await frameContaining("Confirm it's you");
    await t!.mockInput.typeText("wrong-password");
    t!.mockInput.pressEnter();
    await frameContaining("✗");
    await t!.mockInput.typeText(PASSWORD);
    t!.mockInput.pressEnter();
    await frameContaining("Change master password");
    await t!.mockInput.typeText(next);
    t!.mockInput.pressEnter();
    await settle();
    await t!.mockInput.typeText(next);
    t!.mockInput.pressEnter();
    await frameContaining("Master password changed");
    expect(await settle()).not.toContain(next);

    const session = VaultService.unlock(vaultPath, next);
    session.close();
    expect(() => VaultService.unlock(vaultPath, PASSWORD)).toThrow();
  });
});
