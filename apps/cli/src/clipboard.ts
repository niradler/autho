import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";

/**
 * Cross-platform clipboard access for secrets.
 *
 * Native tools are preferred because terminal OSC 52 support is patchy
 * (macOS Terminal.app, GNOME/VTE, conhost and tmux-by-default ignore it).
 * OSC 52 stays as the fallback, and is preferred over SSH where a native
 * tool would write to the remote machine's clipboard instead of the user's.
 */

export type ClipboardTool = {
  name: string;
  copy: { cmd: string; args: string[]; input: (text: string) => string };
  read?: { cmd: string; args: string[]; decode?: (stdout: string) => string };
};

export type CopyResult =
  | { ok: true; method: "native"; tool: string }
  | { ok: true; method: "osc52" }
  | { ok: false; error: string };

type Env = Record<string, string | undefined>;

export type CommandRunner = (cmd: string, args: string[], input: string) => Promise<{ code: number; stdout: string }>;

function encodePowerShell(script: string): string {
  return Buffer.from(script, "utf16le").toString("base64");
}

// The text arrives base64-encoded on stdin so no console code page can mangle it.
// The extra formats keep the secret out of Win+V history and cloud clipboard sync.
const WINDOWS_COPY_SCRIPT = `
$ErrorActionPreference = 'Stop'
$t = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([Console]::In.ReadToEnd().Trim()))
Add-Type -AssemblyName System.Windows.Forms
if ($t.Length -eq 0) { [System.Windows.Forms.Clipboard]::Clear(); exit 0 }
$d = New-Object System.Windows.Forms.DataObject
$d.SetText($t, [System.Windows.Forms.TextDataFormat]::UnicodeText)
foreach ($f in 'CanIncludeInClipboardHistory', 'CanUploadToCloudClipboard', 'ExcludeClipboardContentFromMonitorProcessing') {
  $d.SetData($f, (New-Object IO.MemoryStream(, [byte[]](0, 0, 0, 0))))
}
[System.Windows.Forms.Clipboard]::SetDataObject($d, $true, 5, 100)
`;

const WINDOWS_READ_SCRIPT = `
$t = Get-Clipboard -Raw
if ($null -eq $t) { $t = '' }
[Console]::Out.Write([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($t)))
`;

function windowsTool(exe: string): ClipboardTool {
  const base = ["-NoProfile", "-NonInteractive", "-STA", "-EncodedCommand"];
  return {
    name: exe,
    copy: {
      cmd: exe,
      args: [...base, encodePowerShell(WINDOWS_COPY_SCRIPT)],
      input: (text) => Buffer.from(text, "utf8").toString("base64"),
    },
    read: {
      cmd: exe,
      args: [...base, encodePowerShell(WINDOWS_READ_SCRIPT)],
      decode: (stdout) => Buffer.from(stdout.trim(), "base64").toString("utf8"),
    },
  };
}

export function isRemoteSession(env: Env = process.env): boolean {
  return Boolean(env.SSH_CONNECTION || env.SSH_TTY || env.SSH_CLIENT);
}

/** Ordered list of native clipboard tools worth trying on this machine. */
export function clipboardTools(platform: NodeJS.Platform = process.platform, env: Env = process.env): ClipboardTool[] {
  if (platform === "win32") {
    return [windowsTool("powershell.exe")];
  }

  if (platform === "darwin") {
    // pbcopy picks its encoding from the locale; force UTF-8.
    return [{
      name: "pbcopy",
      copy: { cmd: "env", args: ["LANG=en_US.UTF-8", "pbcopy"], input: (text) => text },
      read: { cmd: "env", args: ["LANG=en_US.UTF-8", "pbpaste"] },
    }];
  }

  const tools: ClipboardTool[] = [];
  if (env.WSL_DISTRO_NAME || env.WSL_INTEROP) {
    tools.push(windowsTool("powershell.exe"));
  }
  if (env.WAYLAND_DISPLAY) {
    tools.push({
      name: "wl-copy",
      copy: { cmd: "wl-copy", args: ["--type", "text/plain;charset=utf-8"], input: (text) => text },
      read: { cmd: "wl-paste", args: ["--no-newline"] },
    });
  }
  if (env.DISPLAY) {
    tools.push(
      {
        name: "xclip",
        copy: { cmd: "xclip", args: ["-selection", "clipboard", "-in"], input: (text) => text },
        read: { cmd: "xclip", args: ["-selection", "clipboard", "-out"] },
      },
      {
        name: "xsel",
        copy: { cmd: "xsel", args: ["--clipboard", "--input"], input: (text) => text },
        read: { cmd: "xsel", args: ["--clipboard", "--output"] },
      },
    );
  }
  if (env.TERMUX_VERSION) {
    tools.push({
      name: "termux-clipboard-set",
      copy: { cmd: "termux-clipboard-set", args: [], input: (text) => text },
      read: { cmd: "termux-clipboard-get", args: [] },
    });
  }
  return tools;
}

export const defaultRunner: CommandRunner = (cmd, args, input) =>
  new Promise((resolve) => {
    let stdout = "";
    let child;
    try {
      // xclip/xsel fork a daemon that owns the selection; ignore its stdio so we don't wait on it.
      child = spawn(cmd, args, { stdio: ["pipe", "pipe", "ignore"], windowsHide: true });
    } catch {
      resolve({ code: -1, stdout: "" });
      return;
    }
    const timer = setTimeout(() => child.kill(), 5000);
    child.stdout?.on("data", (chunk: Buffer) => { stdout += chunk.toString("utf8"); });
    child.on("error", () => { clearTimeout(timer); resolve({ code: -1, stdout: "" }); });
    child.on("close", (code) => { clearTimeout(timer); resolve({ code: code ?? -1, stdout }); });
    child.stdin?.on("error", () => undefined);
    child.stdin?.end(input);
  });

export type ClipboardOptions = {
  /** OSC 52 writer, usually the TUI renderer's. Returns false when unsupported. */
  osc52?: (text: string) => boolean;
  platform?: NodeJS.Platform;
  env?: Env;
  runner?: CommandRunner;
};

export class Clipboard {
  private readonly tools: ClipboardTool[];
  private readonly runner: CommandRunner;
  private readonly osc52?: (text: string) => boolean;
  private readonly preferOsc52: boolean;
  private workingTool: ClipboardTool | null = null;
  private pending: { text: string; timer: ReturnType<typeof setTimeout>; dueAt: number } | null = null;

  constructor(options: ClipboardOptions = {}) {
    const env = options.env ?? process.env;
    this.tools = clipboardTools(options.platform, env);
    this.runner = options.runner ?? defaultRunner;
    this.osc52 = options.osc52;
    this.preferOsc52 = isRemoteSession(env) && Boolean(options.osc52);
  }

  async copy(text: string): Promise<CopyResult> {
    if (this.preferOsc52 && this.osc52?.(text)) {
      return { ok: true, method: "osc52" };
    }

    const candidates = this.workingTool ? [this.workingTool, ...this.tools.filter((t) => t !== this.workingTool)] : this.tools;
    for (const tool of candidates) {
      const result = await this.runner(tool.copy.cmd, tool.copy.args, tool.copy.input(text));
      if (result.code === 0) {
        this.workingTool = tool;
        return { ok: true, method: "native", tool: tool.name };
      }
    }

    if (this.osc52?.(text)) {
      return { ok: true, method: "osc52" };
    }

    const tried = this.tools.map((t) => t.name).join(", ") || "none available";
    return { ok: false, error: `No clipboard available (tried: ${tried}). Use reveal and select the text instead.` };
  }

  /**
   * Copy a secret and clear it after `clearAfterMs`, but only if the clipboard
   * still holds it — never wipe something the user copied afterwards.
   */
  async copySecret(text: string, clearAfterMs: number): Promise<CopyResult> {
    const result = await this.copy(text);
    if (result.ok && clearAfterMs > 0) {
      this.cancelPendingClear();
      const timer = setTimeout(() => { void this.clearIfUnchanged(); }, clearAfterMs);
      timer.unref?.();
      this.pending = { text, timer, dueAt: Date.now() + clearAfterMs };
    }
    return result;
  }

  async read(): Promise<string | null> {
    const tool = this.workingTool ?? this.tools[0];
    if (!tool?.read) {
      return null;
    }
    const result = await this.runner(tool.read.cmd, tool.read.args, "");
    if (result.code !== 0) {
      return null;
    }
    return tool.read.decode ? tool.read.decode(result.stdout) : result.stdout;
  }

  hasPendingClear(): boolean {
    return this.pending !== null;
  }

  async clearIfUnchanged(): Promise<void> {
    const pending = this.pending;
    if (!pending) {
      return;
    }
    this.cancelPendingClear();
    const current = await this.read();
    // Unreadable (e.g. OSC 52 only): clear anyway — a lingering secret is worse.
    if (current === null || current === pending.text) {
      await this.copy("");
    }
  }

  /**
   * On exit the in-process timer dies with us. Copy-then-quit is the normal
   * flow, so instead of wiping the clipboard immediately, hand the pending
   * clear to a detached helper that only receives a hash of the secret.
   * Falls back to clearing now when no native tool is in use.
   */
  handOffPendingClear(): void {
    const pending = this.pending;
    if (!pending) {
      return;
    }
    const remainingMs = Math.max(0, pending.dueAt - Date.now());
    this.cancelPendingClear();
    const tool = this.workingTool;
    if (!tool) {
      // OSC 52 needs our terminal; it's about to go away, so clear now.
      this.osc52?.("");
      return;
    }
    try {
      const child = spawn(selfCommand()[0]!, [...selfCommand().slice(1), CLEAR_COMMAND, String(remainingMs)], {
        detached: true,
        env: { ...process.env, [CLEAR_HASH_ENV]: sha256(pending.text) },
        stdio: "ignore",
        windowsHide: true,
      });
      child.unref();
    } catch {
      spawnSync(tool.copy.cmd, tool.copy.args, { input: tool.copy.input(""), stdio: ["pipe", "ignore", "ignore"], timeout: 5000, windowsHide: true });
    }
  }

  private cancelPendingClear(): void {
    if (this.pending) {
      clearTimeout(this.pending.timer);
      this.pending = null;
    }
  }
}

export const CLEAR_COMMAND = "__clipboard-clear";
export const CLEAR_HASH_ENV = "AUTHO_CLIPBOARD_CLEAR_SHA256";

function sha256(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

/** argv prefix that re-runs this CLI, for both `bun autho.js` and compiled binaries. */
function selfCommand(): string[] {
  const main = typeof Bun !== "undefined" ? Bun.main : process.argv[1] ?? "";
  const compiled = main.startsWith("/$bunfs/") || /^[A-Z]:[\\/]~BUN[\\/]/i.test(main);
  return compiled ? [process.execPath] : [process.execPath, main];
}

/** Body of the detached helper: wait, then clear only if the clipboard still holds the secret. */
export async function runDetachedClear(delayArg: string | undefined, env: Env = process.env): Promise<void> {
  const expected = env[CLEAR_HASH_ENV];
  const delay = Math.min(Math.max(Number(delayArg) || 0, 0), 10 * 60_000);
  if (!expected) {
    return;
  }
  await new Promise((resolve) => setTimeout(resolve, delay));
  const clipboard = new Clipboard({ env });
  const current = await clipboard.read();
  if (current !== null && sha256(current) === expected) {
    await clipboard.copy("");
  }
}
