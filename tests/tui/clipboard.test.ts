import { describe, expect, test } from "bun:test";

import { Clipboard, clipboardTools, type CommandRunner } from "../../apps/cli/src/clipboard.ts";

type Call = { cmd: string; args: string[]; input: string };

/** Fake clipboard backend: `failing` tool commands exit 1, the rest share one buffer. */
function fakeRunner(failing: string[] = []) {
  const calls: Call[] = [];
  const state = { content: "" };
  const runner: CommandRunner = async (cmd, args, input) => {
    calls.push({ cmd, args, input });
    if (failing.includes(cmd)) return { code: 1, stdout: "" };
    const reading = args.includes("-out") || args.includes("--output") || cmd === "wl-paste";
    if (reading) return { code: 0, stdout: state.content };
    state.content = input;
    return { code: 0, stdout: "" };
  };
  return { calls, runner, state };
}

describe("clipboardTools", () => {
  test("picks tools per platform and environment", () => {
    expect(clipboardTools("win32", {}).map((t) => t.name)).toEqual(["powershell.exe"]);
    expect(clipboardTools("darwin", {}).map((t) => t.name)).toEqual(["pbcopy"]);
    expect(clipboardTools("linux", {}).map((t) => t.name)).toEqual([]);
    expect(clipboardTools("linux", { WAYLAND_DISPLAY: "wayland-0", DISPLAY: ":0" }).map((t) => t.name))
      .toEqual(["wl-copy", "xclip", "xsel"]);
    expect(clipboardTools("linux", { WSL_DISTRO_NAME: "Ubuntu", DISPLAY: ":0" }).map((t) => t.name))
      .toEqual(["powershell.exe", "xclip", "xsel"]);
  });

  test("windows copy keeps secrets out of clipboard history and passes text as base64", () => {
    const [tool] = clipboardTools("win32", {});
    const script = Buffer.from(tool!.copy.args.at(-1)!, "base64").toString("utf16le");
    expect(script).toContain("ExcludeClipboardContentFromMonitorProcessing");
    expect(script).toContain("CanIncludeInClipboardHistory");
    expect(tool!.copy.input("pässwörd")).toBe(Buffer.from("pässwörd", "utf8").toString("base64"));
    expect(tool!.copy.args).toContain("-STA");
  });
});

describe("Clipboard", () => {
  test("falls back through native tools and remembers the one that worked", async () => {
    const fake = fakeRunner(["xclip"]);
    const clipboard = new Clipboard({ platform: "linux", env: { DISPLAY: ":0" }, runner: fake.runner });
    expect(await clipboard.copy("one")).toEqual({ ok: true, method: "native", tool: "xsel" });
    fake.calls.length = 0;
    await clipboard.copy("two");
    expect(fake.calls.map((c) => c.cmd)).toEqual(["xsel"]);
    expect(fake.state.content).toBe("two");
  });

  test("uses OSC 52 when no native tool works and reports failure when nothing does", async () => {
    const written: string[] = [];
    const osc = new Clipboard({ platform: "linux", env: {}, runner: fakeRunner().runner, osc52: (t) => { written.push(t); return true; } });
    expect(await osc.copy("secret")).toEqual({ ok: true, method: "osc52" });
    expect(written).toEqual(["secret"]);

    const none = new Clipboard({ platform: "linux", env: {}, runner: fakeRunner().runner, osc52: () => false });
    const result = await none.copy("secret");
    expect(result.ok).toBe(false);
  });

  test("prefers OSC 52 over SSH so the copy lands on the local machine", async () => {
    const fake = fakeRunner();
    const written: string[] = [];
    const clipboard = new Clipboard({ platform: "linux", env: { DISPLAY: ":0", SSH_CONNECTION: "1 2 3 4" }, runner: fake.runner, osc52: (t) => { written.push(t); return true; } });
    expect(await clipboard.copy("x")).toEqual({ ok: true, method: "osc52" });
    expect(fake.calls).toHaveLength(0);
  });

  test("clears a copied secret only while the clipboard still holds it", async () => {
    const fake = fakeRunner();
    const clipboard = new Clipboard({ platform: "linux", env: { DISPLAY: ":0" }, runner: fake.runner });

    await clipboard.copySecret("hunter2", 60_000);
    expect(clipboard.hasPendingClear()).toBe(true);
    await clipboard.clearIfUnchanged();
    expect(fake.state.content).toBe("");
    expect(clipboard.hasPendingClear()).toBe(false);

    await clipboard.copySecret("hunter2", 60_000);
    fake.state.content = "something the user copied later";
    await clipboard.clearIfUnchanged();
    expect(fake.state.content).toBe("something the user copied later");
  });

  test("the timed clear fires on its own", async () => {
    const fake = fakeRunner();
    const clipboard = new Clipboard({ platform: "linux", env: { DISPLAY: ":0" }, runner: fake.runner });
    await clipboard.copySecret("hunter2", 20);
    await Bun.sleep(80);
    expect(fake.state.content).toBe("");
  });
});
