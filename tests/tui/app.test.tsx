import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { VaultService, configFilePath, resetConfigCache, type VaultSession } from "../../packages/core/src/index.ts";
import { Clipboard, type CommandRunner } from "../../apps/cli/src/clipboard.ts";
import { App } from "../../apps/cli/src/tui.tsx";
import type { PasskeyRunner } from "../../apps/cli/src/tui/unlock.tsx";
import type { WebStatus } from "../../apps/cli/src/tui/settings.tsx";
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

async function renderUnlocked(width = 120, revealMs = 30_000, web?: WebStatus): Promise<void> {
  t = await render(
    <App vaultPath={vaultPath} clipboard={fakeClipboard()} revealMs={revealMs} clipboardClearMs={30_000} idleLockMs={0} onQuit={() => { quits += 1; }} sessionSink={sink} web={web} />,
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
  test("the header shows the page tabs and the command palette key stays pinned", async () => {
    await renderUnlocked(160);
    const frame = await settle();
    for (const tab of ["1 Vault", "2 Groups", "3 Leases", "4 Audit", "5 Integrity", "6 Settings"]) expect(frame).toContain(tab);
    expect(frame).toContain("commands");
  });

  test("number keys switch tabs and esc returns to the vault", async () => {
    await renderUnlocked();
    t!.mockInput.pressKey("3");
    await frameContaining("No active leases");
    t!.mockInput.pressKey("4");
    await frameContaining("filter by event");
    t!.mockInput.pressKey("5");
    await frameContaining("Vault seal");
    t!.mockInput.pressEscape();
    await frameContaining("octocat");
  });

  test("leases: create one over a secret, then revoke it", async () => {
    await renderUnlocked();
    t!.mockInput.pressKey("3");
    await frameContaining("No active leases");
    t!.mockInput.pressKey("n");
    await frameContaining("New lease");
    await settle();
    await t!.mockInput.typeText("ci");
    t!.mockInput.pressTab();
    t!.mockInput.pressTab();
    await settle();
    t!.mockInput.pressEnter();
    await frameContaining("1 picked");
    t!.mockInput.pressKey("s", { ctrl: true });
    await frameContaining("expires in 1h");
    const [lease] = sink.current!.listLeases(10);
    expect(lease!.name).toBe("ci");
    expect(sink.current!.showLease(lease!.id).coverage.map((c) => c.name)).toEqual(["github"]);
    t!.mockInput.pressKey("x");
    await frameContaining('Revoke "ci"?');
    t!.mockInput.pressKey("y");
    await frameContaining('Revoked "ci"');
    expect(sink.current!.showLease(lease!.id).lease.revokedAt).not.toBeNull();
  });

  test("leases: a bad duration is rejected without creating anything", async () => {
    await renderUnlocked();
    t!.mockInput.pressKey("3");
    await frameContaining("No active leases");
    t!.mockInput.pressKey("n");
    await frameContaining("New lease");
    await settle();
    t!.mockInput.pressTab();
    await settle();
    await t!.mockInput.typeText("x");
    t!.mockInput.pressKey("s", { ctrl: true });
    await frameContaining("use a duration like");
    expect(sink.current!.listLeases(10)).toEqual([]);
  });

  test("audit: lists events and filters them", async () => {
    await renderUnlocked();
    t!.mockInput.pressKey("4");
    await frameContaining("events · last 100");
    t!.mockInput.pressKey("/");
    await settle();
    await t!.mockInput.typeText("zzz-nothing");
    await frameContaining('No events match "zzz-nothing"');
    t!.mockInput.pressEscape();
    await frameContaining("filter by event");
    t!.mockInput.pressKey("m");
    await frameContaining("last 200");
  });

  test("integrity: a change made outside autho is shown and undone after the password", async () => {
    const setup = VaultService.unlock(vaultPath, PASSWORD);
    setup.addSecret({ name: "aws", type: "password", value: "aws-value" });
    const [github, aws] = [setup.getSecret("github").id, setup.getSecret("aws").id];
    setup.close();
    const raw = new Database(vaultPath);
    raw.query("INSERT INTO secret_links (primary_id, linked_id, created_at) VALUES (?1, ?2, ?3)").run(github, aws, new Date().toISOString());
    raw.close();

    await renderUnlocked();
    t!.mockInput.pressKey("5");
    await frameContaining("Changed outside autho");
    expect(await frameContaining("secret_links")).toContain("added");
    t!.mockInput.pressKey("u");
    await frameContaining("Master password");
    await settle();
    await t!.mockInput.typeText("wrong-password");
    t!.mockInput.pressEnter();
    await frameContaining("Invalid vault password");
    await t!.mockInput.typeText(PASSWORD);
    t!.mockInput.pressEnter();
    await frameContaining("Re-sealed");
    await frameContaining("Intact");
    expect(sink.current!.getLinks("github").links).toEqual([]);
  });

  test("integrity: shows an intact seal and imports a legacy backup", async () => {
    const backup = join(dir, "legacy.json");
    writeFileSync(backup, JSON.stringify([{ name: "legacy-api", type: "note", value: "abc" }]));
    await renderUnlocked();
    t!.mockInput.pressKey("5");
    await frameContaining("Intact");
    t!.mockInput.pressArrow("down");
    t!.mockInput.pressEnter();
    await frameContaining("enter to import");
    await settle();
    await t!.mockInput.typeText(backup);
    t!.mockInput.pressEnter();
    await frameContaining("Imported 1 secret");
    expect(sink.current!.listSecretIndex().map((s) => s.name)).toContain("legacy-api");
  });

  test("tab moves into the actions, arrows pick one and enter runs it", async () => {
    await renderUnlocked();
    t!.mockInput.pressTab();
    await frameContaining("choose");
    // copy · reveal · open · edit · link · delete — five quick presses land on delete.
    t!.mockInput.pressArrow("right");
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
    t!.mockInput.pressKey("6");
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

describe("Links", () => {
  const OTP_SEED = "JBSWY3DPEHPK3PXP";

  test("l opens the picker and enter links the highlighted secret", async () => {
    await renderUnlocked();
    sink.current!.addSecret({ name: "github-otp", type: "otp", value: OTP_SEED });
    t!.mockInput.pressKey("r");
    await settle();
    t!.mockInput.pressKey("l");
    await frameContaining("Link to github");
    await t!.mockInput.typeText("otp");
    t!.mockInput.pressEnter();
    await frameContaining("Linked github-otp");
    t!.mockInput.pressEscape();
    const frame = await frameContaining("press t for the code");
    expect(frame).toContain("github ·1");
    expect(sink.current!.getLinks("github").links.map((l) => l.name)).toEqual(["github-otp"]);
  });

  test("enter on a linked secret in the picker unlinks it", async () => {
    await renderUnlocked();
    sink.current!.addSecret({ name: "github-otp", type: "otp", value: OTP_SEED });
    sink.current!.linkSecrets("github", "github-otp");
    t!.mockInput.pressKey("r");
    await frameContaining("press t for the code");
    t!.mockInput.pressKey("l");
    await frameContaining("Link to github");
    t!.mockInput.pressEnter();
    await frameContaining("Unlinked github-otp");
    expect(sink.current!.getLinks("github").links).toEqual([]);
  });

  test("t shows and copies the linked OTP code without revealing the password", async () => {
    await renderUnlocked();
    sink.current!.addSecret({ name: "github-otp", type: "otp", value: OTP_SEED });
    sink.current!.linkSecrets("github", "github-otp");
    t!.mockInput.pressKey("r");
    await frameContaining("press t for the code");
    t!.mockInput.pressKey("t");
    await frameContaining("OTP code copied");
    const code = sink.current!.generateOtp("github-otp", { audit: false }).code;
    expect(copies.at(-1)).toMatch(/^\d{6}$/);
    const frame = await settle();
    expect(frame).toContain(`${code.slice(0, 3)} ${code.slice(3)}`);
    expect(frame).not.toContain(SECRET);
  });

  test("delete offers to remove linked secrets too", async () => {
    await renderUnlocked();
    sink.current!.addSecret({ name: "github-otp", type: "otp", value: OTP_SEED });
    sink.current!.linkSecrets("github", "github-otp");
    t!.mockInput.pressKey("r");
    await frameContaining("press t for the code");
    t!.mockInput.pressKey("d");
    await frameContaining("a = also its 1 linked");
    t!.mockInput.pressKey("a");
    await frameContaining('Deleted "github" and github-otp');
    expect(sink.current!.listSecretIndex()).toEqual([]);
  });

  test("y in the delete prompt keeps the linked secrets", async () => {
    await renderUnlocked();
    sink.current!.addSecret({ name: "github-otp", type: "otp", value: OTP_SEED });
    sink.current!.linkSecrets("github", "github-otp");
    t!.mockInput.pressKey("r");
    await frameContaining("press t for the code");
    t!.mockInput.pressKey("d");
    await frameContaining("y = only this");
    t!.mockInput.pressKey("y");
    await frameContaining('Deleted "github"');
    expect(sink.current!.listSecretIndex().map((e) => e.name)).toEqual(["github-otp"]);
  });

  test("the palette goes to a linked secret", async () => {
    await renderUnlocked();
    sink.current!.addSecret({ name: "recovery-codes", type: "note", value: "a b c" });
    sink.current!.linkSecrets("github", "recovery-codes");
    t!.mockInput.pressKey("r");
    await frameContaining("recovery-codes");
    t!.mockInput.pressKey("k", { ctrl: true });
    await frameContaining("Commands");
    await settle();
    await t!.mockInput.typeText("go to recovery");
    t!.mockInput.pressEnter();
    await frameContaining("Linked from  github");
  });

  test("a linked secret shows which secret links to it", async () => {
    await renderUnlocked();
    sink.current!.addSecret({ name: "github-otp", type: "otp", value: OTP_SEED });
    sink.current!.linkSecrets("github", "github-otp");
    t!.mockInput.pressKey("r");
    await settle();
    t!.mockInput.pressArrow("down");
    const frame = await frameContaining("Linked from");
    expect(frame).toContain("Linked from  github");
  });
});

describe("Groups", () => {
  test("the Groups tab creates a group and deletes it after confirming, ungrouping its secrets", async () => {
    await renderUnlocked();
    t!.mockInput.pressKey("2");
    await frameContaining("No groups yet");
    t!.mockInput.pressKey("n");
    await frameContaining("New group");
    await settle();
    await t!.mockInput.typeText("homelab");
    t!.mockInput.pressEnter();
    await frameContaining('Created group "homelab"');
    sink.current!.updateSecret("github", { group: "homelab" });
    t!.mockInput.pressKey("r");
    await frameContaining("1 group");
    t!.mockInput.pressKey("x");
    await frameContaining("1 secret become ungrouped, none deleted");
    t!.mockInput.pressKey("y");
    await frameContaining('Deleted group "homelab"');
    expect(sink.current!.listGroups()).toEqual([]);
    expect(sink.current!.describeSecret("github").group).toBeNull();
  });

  test("enter on a group opens the vault narrowed to it; esc clears the filter, then the group", async () => {
    const setup = VaultService.unlock(vaultPath, PASSWORD);
    setup.createGroup("homelab");
    setup.addSecret({ group: "homelab", name: "proxmox", type: "password", value: "pw" });
    setup.addSecret({ group: "homelab", name: "nas", type: "password", value: "pw" });
    setup.close();

    await renderUnlocked();
    t!.mockInput.pressKey("2");
    await frameContaining("1 group");
    t!.mockInput.pressEnter();
    let frame = await frameContaining("homelab · 2 secrets");
    expect(frame).not.toContain("octocat");
    t!.mockInput.pressKey("/");
    await settle();
    await t!.mockInput.typeText("prox");
    await frameContaining("homelab · 1/2 secrets");
    t!.mockInput.pressEscape();
    await frameContaining("homelab · 2 secrets");
    t!.mockInput.pressEscape();
    frame = await frameContaining("3/3 secrets");
    expect(frame).toContain("octocat");
  });

  test("the palette jumps to a group and to the ungrouped secrets", async () => {
    const setup = VaultService.unlock(vaultPath, PASSWORD);
    setup.createGroup("homelab");
    setup.addSecret({ group: "homelab", name: "proxmox", type: "password", value: "pw" });
    setup.close();

    await renderUnlocked();
    t!.mockInput.pressKey("k", { ctrl: true });
    await frameContaining("Commands");
    await settle();
    await t!.mockInput.typeText("group homelab");
    await frameContaining("Group · homelab");
    t!.mockInput.pressEnter();
    const frame = await frameContaining("homelab · 1 secrets");
    expect(frame).toContain("Group       homelab");
    t!.mockInput.pressKey("k", { ctrl: true });
    await frameContaining("Commands");
    await settle();
    await t!.mockInput.typeText("ungrouped");
    await frameContaining("Group · (ungrouped)");
    t!.mockInput.pressEnter();
    expect(await frameContaining("(ungrouped) · 1 secrets")).toContain("octocat");
  });

  test("a in the Groups tab adds secrets to the group and enter again takes them out", async () => {
    const setup = VaultService.unlock(vaultPath, PASSWORD);
    setup.createGroup("homelab");
    setup.close();

    await renderUnlocked();
    t!.mockInput.pressKey("2");
    await frameContaining("1 group");
    t!.mockInput.pressKey("a");
    await frameContaining("Add to homelab");
    await settle();
    await t!.mockInput.typeText("github");
    t!.mockInput.pressEnter();
    await frameContaining("Added github to homelab");
    expect(sink.current!.describeSecret("github").group).toBe("homelab");
    t!.mockInput.pressEnter();
    await frameContaining("Removed github from homelab");
    expect(sink.current!.describeSecret("github").group).toBeNull();
    t!.mockInput.pressEnter();
    await frameContaining("Added github to homelab");
    t!.mockInput.pressEscape();
    await settle();
    await t!.renderOnce();
    expect(t!.captureCharFrame()).not.toContain("Add to homelab");
    expect(sink.current!.describeSecret("github").group).toBe("homelab");
  });

  test("the mouse wheel scrolls the vault list and the add-secrets picker without dropping ticks", async () => {
    const setup = VaultService.unlock(vaultPath, PASSWORD);
    setup.createGroup("homelab");
    for (let i = 0; i < 30; i++) setup.addSecret({ name: `s${String(i).padStart(2, "0")}`, type: "password", value: "pw" });
    setup.close();

    await renderUnlocked();
    await frameContaining("31/31 secrets");
    for (let i = 0; i < 5; i++) await t!.mockMouse.scroll(10, 10, "down");
    await settle();
    t!.mockInput.pressKey("e");
    await frameContaining("leave empty to keep the current value");
    expect(t!.captureCharFrame()).toContain("Edit s14");
    t!.mockInput.pressEscape();
    await frameContaining("31/31 secrets");

    t!.mockInput.pressKey("2");
    await frameContaining("1 group");
    t!.mockInput.pressKey("a");
    await frameContaining("Add to homelab");
    await settle();
    // Over the picker the wheel scrolls its list, not the groups list behind it; enter takes the row under the pointer.
    for (let i = 0; i < 5; i++) await t!.mockMouse.scroll(30, 10, "down");
    await settle();
    t!.mockInput.pressEnter();
    await frameContaining("Added s17 to homelab");
  });

  test("the secret form picks an existing group", async () => {
    const setup = VaultService.unlock(vaultPath, PASSWORD);
    setup.createGroup("homelab");
    setup.close();

    await renderUnlocked();
    t!.mockInput.pressKey("e");
    await frameContaining("leave empty to keep the current value");
    t!.mockInput.pressArrow("down");
    await frameContaining("enter to choose");
    t!.mockInput.pressEnter();
    await frameContaining("search groups");
    await settle();
    await t!.mockInput.typeText("home");
    t!.mockInput.pressEnter();
    await settle();
    t!.mockInput.pressKey("s", { ctrl: true });
    await frameContaining('Saved "github"');
    expect(sink.current!.describeSecret("github").group).toBe("homelab");
  });
});

describe("Settings", () => {
  async function openSettings(): Promise<void> {
    await renderUnlocked();
    t!.mockInput.pressKey("6");
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

  test("shows the web UI served alongside the TUI", async () => {
    await renderUnlocked(120, 30_000, { url: "http://localhost:8061", note: "running while the TUI is open" });
    t!.mockInput.pressKey("6");
    await frameContaining("Vault file");
    const frame = await goToSection("Agents & services");
    expect(frame).toContain("Web UI with TUI");
    expect(frame).toContain("http://localhost:8061");
  });

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
