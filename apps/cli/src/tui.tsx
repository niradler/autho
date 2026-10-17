import { basename } from "node:path";

import { createCliRenderer, type CliRenderer } from "@opentui/core";
import { createRoot, useKeyboard, useRenderer, useSelectionHandler } from "@opentui/react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { booleanPreference, defaultVaultPath, numberPreference } from "../../../packages/core/src/index.ts";
import type { SecretRecord, VaultSession } from "../../../packages/core/src/index.ts";
import { closeSessionAndRecordSeal } from "../../../packages/core/src/os-secrets.ts";
import { createWebServer, type WebServer } from "../../web/src/server.ts";
import { Clipboard } from "./clipboard.ts";
import { Header, StatusBar, type KeyHint } from "./tui/components.tsx";
import { AppContext, describeCopy, type AppApi, type Command, type CopyTarget, type Timings, type Toast, type ToastKind } from "./tui/context.tsx";
import { SecretForm } from "./tui/form.tsx";
import { CommandPalette } from "./tui/palette.tsx";
import { SettingsScreen, type WebStatus } from "./tui/settings.tsx";
import { TIMINGS, theme } from "./tui/theme.ts";
import { UnlockScreen, type PasskeyRunner } from "./tui/unlock.tsx";
import { VaultScreen } from "./tui/vault.tsx";

type Route =
  | { name: "unlock"; notice?: string }
  | { name: "vault"; focusId?: string }
  | { name: "form"; editing: SecretRecord | null }
  | { name: "settings" };

export type TuiOptions = {
  vaultPath: string;
  clipboard: Clipboard;
  revealMs: number;
  clipboardClearMs: number;
  idleLockMs: number;
  /** Called once the user quits; tears the renderer down. */
  onQuit: () => void;
  /** Mirrors the open session so shutdown can close it on any exit path. */
  sessionSink?: { current: VaultSession | null };
  /** Test seam for the browser passkey ceremony. */
  passkeyRunner?: PasskeyRunner;
  /** The web UI served alongside this TUI, shown in Settings. */
  web?: WebStatus;
};

export function App({ vaultPath, clipboard, revealMs: initialRevealMs, clipboardClearMs: initialClipboardClearMs, idleLockMs: initialIdleLockMs, onQuit, sessionSink, passkeyRunner, web }: TuiOptions) {
  const renderer = useRenderer();
  const [timings, setTimingsState] = useState<Timings>({ revealMs: initialRevealMs, clipboardClearMs: initialClipboardClearMs, idleLockMs: initialIdleLockMs });
  const { revealMs, clipboardClearMs, idleLockMs } = timings;
  const setTimings = useCallback((next: Partial<Timings>) => setTimingsState((prev) => ({ ...prev, ...next })), []);
  const [route, setRoute] = useState<Route>({ name: "unlock" });
  const [session, setSession] = useState<VaultSession | null>(null);
  const [toastState, setToastState] = useState<Toast | null>(null);
  const [hints, setHints] = useState<KeyHint[]>([]);
  const [paletteOpen, setPaletteOpen] = useState(false);

  const commandsRef = useRef<Command[]>([]);
  const copyTargetRef = useRef<CopyTarget | null>(null);
  const sessionRef = useRef<VaultSession | null>(null);
  sessionRef.current = session;
  if (sessionSink) sessionSink.current = session;
  const lastCtrlC = useRef(0);
  const lastActivity = useRef(Date.now());
  const toastTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const quitting = useRef(false);

  const toast = useCallback((message: string, kind: ToastKind = "success") => {
    if (toastTimer.current) clearTimeout(toastTimer.current);
    setToastState({ message, kind });
    toastTimer.current = setTimeout(() => setToastState(null), TIMINGS.toastMs);
  }, []);

  useEffect(() => () => { if (toastTimer.current) clearTimeout(toastTimer.current); }, []);

  const copy = useCallback(async (label: string, text: string, options: { secret?: boolean } = {}) => {
    const clearMs = options.secret ? clipboardClearMs : 0;
    const result = options.secret ? await clipboard.copySecret(text, clearMs) : await clipboard.copy(text);
    const message = describeCopy(label, result, clearMs ? Math.round(clearMs / 1000) : null);
    toast(message.message, message.kind);
    return result;
  }, [clipboard, clipboardClearMs, toast]);

  const lock = useCallback((notice = "Vault locked") => {
    const current = sessionRef.current;
    if (!current) return;
    void closeSessionAndRecordSeal(vaultPath, current);
    setSession(null);
    setPaletteOpen(false);
    setRoute({ name: "unlock", notice });
  }, [vaultPath]);

  const quit = useCallback(() => {
    if (quitting.current) return;
    quitting.current = true;
    onQuit();
  }, [onQuit]);

  const openPalette = useCallback(() => setPaletteOpen(true), []);

  const api = useMemo<AppApi>(() => ({
    active: !paletteOpen,
    toast,
    copy,
    lock: () => lock(),
    quit,
    openPalette,
    setTimings,
    commandsRef,
    copyTargetRef,
  }), [paletteOpen, toast, copy, lock, quit, openPalette, setTimings]);

  /**
   * Ctrl+C never exits straight away. The first press copies the mouse
   * selection (or the focused value); a second press within the window quits.
   */
  const handleCtrlC = useCallback(async () => {
    const now = Date.now();
    if (now - lastCtrlC.current < TIMINGS.quitWindowMs) {
      quit();
      return;
    }
    lastCtrlC.current = now;
    const suffix = " — ctrl+c again to quit";

    const selected = renderer.getSelection()?.getSelectedText() ?? "";
    if (selected) {
      renderer.clearSelection();
      // Selections can include a revealed secret, so they get the timed clear too.
      const result = await clipboard.copySecret(selected, clipboardClearMs);
      const message = describeCopy("Selection", result, Math.round(clipboardClearMs / 1000));
      toast(message.message + suffix, message.kind);
      return;
    }

    const target = copyTargetRef.current;
    const value = target ? safeRead(target) : null;
    if (target && value) {
      const clearMs = target.secret ? clipboardClearMs : 0;
      const result = target.secret ? await clipboard.copySecret(value, clearMs) : await clipboard.copy(value);
      const message = describeCopy(target.label, result, clearMs ? Math.round(clearMs / 1000) : null);
      toast(message.message + suffix, message.kind);
      return;
    }
    toast("Press ctrl+c again to quit", "info");
  }, [renderer, clipboard, clipboardClearMs, quit, toast]);

  useKeyboard((key) => {
    lastActivity.current = Date.now();
    if (!key.ctrl || key.meta) return;
    if (key.name === "c") {
      key.preventDefault();
      void handleCtrlC();
      return;
    }
    if (key.name === "k" && !paletteOpen) {
      key.preventDefault();
      openPalette();
      return;
    }
    if (key.name === "l" && sessionRef.current) {
      key.preventDefault();
      lock();
    }
  });

  useSelectionHandler((selection) => {
    if (selection.isDragging) return;
    const text = selection.getSelectedText();
    if (text) toast(`Selected ${[...text].length} characters — ctrl+c to copy`, "info");
  });

  // Idle auto-lock. Keyboard and mouse both count as activity.
  useEffect(() => {
    if (!session || idleLockMs <= 0) return;
    lastActivity.current = Date.now();
    const timer = setInterval(() => {
      if (Date.now() - lastActivity.current >= idleLockMs) {
        lock(`Locked after ${Math.round(idleLockMs / 60_000) || 1} min of inactivity`);
      }
    }, Math.min(5000, idleLockMs));
    return () => clearInterval(timer);
  }, [session, idleLockMs, lock]);

  const onUnlock = useCallback((next: VaultSession) => {
    setSession(next);
    setRoute({ name: "vault" });
  }, []);

  const onEdit = useCallback((id: string) => {
    const current = sessionRef.current;
    if (!current) return;
    try {
      // The form loads the stored value only on Ctrl+R; drop it here.
      const record = current.getSecret(id);
      setRoute({ name: "form", editing: { ...record, value: "" } });
    } catch (e) {
      toast(e instanceof Error ? e.message : String(e), "error");
    }
  }, [toast]);

  const globalCommands: Command[] = [
    ...(session ? [
      { id: "settings", title: "Settings", hint: ",", group: "App", run: () => setRoute({ name: "settings" }) },
      { id: "lock", title: "Lock vault", hint: "ctrl+l", group: "App", run: () => lock() },
    ] : []),
    { id: "quit", title: "Quit", hint: "ctrl+c ×2", group: "App", run: quit },
  ];

  const goVault = useCallback(() => setRoute({ name: "vault" }), []);
  const goSettings = useCallback(() => setRoute({ name: "settings" }), []);
  // Pinned at the right of the status bar so the way to Settings and the palette is always visible.
  const globalHints: KeyHint[] = !session || route.name === "unlock" ? []
    : route.name === "vault" ? [["ctrl+k", "commands"], [",", "settings"]]
      : [["ctrl+k", "commands"]];

  const title = route.name === "unlock" ? "Locked" : route.name === "form" ? (route.editing ? "Edit secret" : "New secret") : route.name === "settings" ? "Settings" : "Vault";
  const vaultName = basename(vaultPath);

  let screen;
  if (route.name === "unlock" || !session) {
    screen = <UnlockScreen key={`unlock:${route.name === "unlock" ? route.notice ?? "" : ""}`} vaultPath={vaultPath} onUnlock={onUnlock} setHints={setHints} notice={route.name === "unlock" ? route.notice : undefined} passkeyRunner={passkeyRunner} />;
  } else if (route.name === "form") {
    screen = (
      <SecretForm
        session={session}
        editing={route.editing}
        setHints={setHints}
        revealMs={revealMs}
        onCancel={() => setRoute({ name: "vault", focusId: route.editing?.id })}
        onDone={(message, id) => { toast(message); setRoute({ name: "vault", focusId: id }); }}
      />
    );
  } else if (route.name === "settings") {
    screen = <SettingsScreen vaultPath={vaultPath} setHints={setHints} onBack={goVault} passkeyRunner={passkeyRunner} web={web} />;
  } else {
    screen = (
      <VaultScreen
        key={route.focusId ?? "vault"}
        session={session}
        initialSelectedId={route.focusId}
        onCreate={() => setRoute({ name: "form", editing: null })}
        onEdit={onEdit}
        onSettings={goSettings}
        setHints={setHints}
        revealMs={revealMs}
      />
    );
  }

  return (
    <AppContext.Provider value={api}>
      <box
        flexDirection="column"
        width="100%"
        height="100%"
        onMouseDown={() => { lastActivity.current = Date.now(); }}
        onMouseScroll={() => { lastActivity.current = Date.now(); }}
      >
        <Header
          title={title}
          right={<text fg={theme.dim}>{session ? <span fg={theme.success}>● unlocked</span> : <span fg={theme.muted}>○ locked</span>}  {vaultName}</text>}
        />
        <box flexDirection="column" flexGrow={1}>{screen}</box>
        <StatusBar hints={hints} pinned={globalHints} toast={toastState} />
        {paletteOpen ? <CommandPalette commands={[...commandsRef.current, ...globalCommands]} onClose={() => setPaletteOpen(false)} /> : null}
      </box>
    </AppContext.Provider>
  );
}

function safeRead(target: CopyTarget): string | null {
  try {
    return target.read();
  } catch {
    return null;
  }
}

/**
 * Serves the web UI next to the TUI. It keeps its own sessions, so the browser
 * unlocks separately; a busy port (another autho, `web serve`) just skips it.
 */
function startCompanionWeb(vaultPath: string): { server: WebServer | null; status: WebStatus } {
  if (!booleanPreference("webWithTui")) return { server: null, status: { url: null, note: "off" } };
  try {
    const server = createWebServer({ vaultPath });
    return { server, status: { url: server.url, note: "running while the TUI is open" } };
  } catch (error) {
    const busy = (error as { code?: string }).code === "EADDRINUSE";
    const note = busy ? `not started: port ${numberPreference("webPort")} is in use` : `not started: ${error instanceof Error ? error.message : String(error)}`;
    return { server: null, status: { url: null, note } };
  }
}

export async function runTui(vaultPath?: string): Promise<void> {
  const vault = vaultPath ?? defaultVaultPath();
  const web = startCompanionWeb(vault);
  const renderer: CliRenderer = await createCliRenderer({ exitOnCtrlC: false, useMouse: booleanPreference("mouse") });
  const clipboard = new Clipboard({
    osc52: (text) => (text ? renderer.copyToClipboardOSC52(text) : renderer.clearClipboardOSC52()),
  });

  const sessionSink: { current: VaultSession | null } = { current: null };
  // Runs for quit and for signals alike: hand the clipboard clear to a helper and close the DB.
  renderer.once("destroy", () => {
    web.server?.stop();
    clipboard.handOffPendingClear();
    // The session closes synchronously; the keychain write after it is best effort.
    if (sessionSink.current) void closeSessionAndRecordSeal(vault, sessionSink.current).catch(() => { /* already closed */ });
    sessionSink.current = null;
  });

  createRoot(renderer).render(
    <App
      vaultPath={vault}
      clipboard={clipboard}
      revealMs={numberPreference("revealSeconds") * 1000}
      clipboardClearMs={numberPreference("clipboardClearSeconds") * 1000}
      idleLockMs={numberPreference("idleLockSeconds") * 1000}
      onQuit={() => renderer.destroy()}
      sessionSink={sessionSink}
      web={web.status}
    />,
  );
}
