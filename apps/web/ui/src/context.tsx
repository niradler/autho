import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { toast } from "sonner";

import { api, errorMessage, setCsrf, type Prefs, type SessionInfo } from "./lib/api.ts";

export type Screen = "vault" | "groups" | "leases" | "audit" | "health" | "settings";

export type Command = {
  id: string;
  title: string;
  group: string;
  hint?: string;
  keywords?: string;
  run: () => void;
};

/** The vault list's group scope; a null id is the "(ungrouped)" row. */
export type GroupFilter = { id: string | null; name: string };

export type KeyHint = [key: string, label: string];

type AppValue = {
  session: SessionInfo;
  prefs: Prefs;
  setPrefs: (prefs: Prefs) => void;
  screen: Screen;
  go: (screen: Screen) => void;
  /** Scopes the vault list to one group (null shows every secret). */
  vaultGroup: GroupFilter | null;
  /** Opens the vault scoped to a group, or clears the scope with null. */
  openGroup: (group: GroupFilter | null) => void;
  lock: (reason?: string) => void;
  /** Copies text; secrets are wiped from the clipboard after the clipboard-clear preference. */
  copy: (label: string, text: string, secret?: boolean) => Promise<void>;
  /** Commands the current screen adds to the palette. */
  setScreenCommands: (commands: Command[]) => void;
  screenCommands: Command[];
  setHints: (hints: KeyHint[]) => void;
  hints: KeyHint[];
  paletteOpen: boolean;
  setPaletteOpen: (open: boolean) => void;
  /** True while a dialog owns the keyboard, so screen shortcuts stand down. */
  modalOpen: boolean;
  setModalOpen: (open: boolean) => void;
};

const AppContext = createContext<AppValue | null>(null);

export function useApp(): AppValue {
  const value = useContext(AppContext);
  if (!value) throw new Error("useApp outside AppProvider");
  return value;
}

/** Registers palette commands and status-bar hints for the mounted screen. */
export function useScreen(commands: Command[], hints: KeyHint[]): void {
  const { setScreenCommands, setHints } = useApp();
  useEffect(() => {
    setScreenCommands(commands);
  }, [commands, setScreenCommands]);
  const hintKey = JSON.stringify(hints);
  useEffect(() => {
    setHints(JSON.parse(hintKey) as KeyHint[]);
  }, [hintKey, setHints]);
  useEffect(() => () => setScreenCommands([]), [setScreenCommands]);
}

const HEARTBEAT_MS = 60_000;
const ACTIVITY_EVENTS = ["pointerdown", "keydown", "wheel", "touchstart", "pointermove"] as const;

export function AppProvider({ session, onLocked, children }: { session: SessionInfo; onLocked: (reason?: string) => void; children: ReactNode }) {
  const [prefs, setPrefs] = useState<Prefs>(session.prefs);
  const [screen, setScreen] = useState<Screen>(() => (location.hash.slice(1) as Screen) || "vault");
  const [vaultGroup, setVaultGroup] = useState<GroupFilter | null>(null);
  const [screenCommands, setScreenCommands] = useState<Command[]>([]);
  const [hints, setHints] = useState<KeyHint[]>([]);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [modalOpen, setModalOpen] = useState(false);
  const clipboardTimer = useRef<number | null>(null);
  const lastActivity = useRef(Date.now());
  const lastBeat = useRef(Date.now());
  const locking = useRef(false);

  const go = useCallback((next: Screen) => {
    setScreen(next);
    history.replaceState(null, "", `#${next}`);
  }, []);

  const openGroup = useCallback((group: GroupFilter | null) => {
    setVaultGroup(group);
    go("vault");
  }, [go]);

  const lock = useCallback((reason?: string) => {
    if (locking.current) return;
    locking.current = true;
    void api.lock().catch(() => {}).finally(() => {
      setCsrf(null);
      onLocked(reason);
    });
  }, [onLocked]);

  const copy = useCallback(async (label: string, text: string, secret = false) => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      toast.error("The browser blocked clipboard access");
      return;
    }
    if (clipboardTimer.current !== null) window.clearTimeout(clipboardTimer.current);
    if (secret && prefs.clipboardClearSeconds > 0) {
      clipboardTimer.current = window.setTimeout(() => {
        // Best effort: browsers only allow writes while the page has focus.
        void navigator.clipboard.writeText("").catch(() => {});
        clipboardTimer.current = null;
      }, prefs.clipboardClearSeconds * 1000);
      toast.success(`${label} copied`, { description: `Clipboard clears in ${prefs.clipboardClearSeconds}s` });
    } else {
      toast.success(`${label} copied`);
    }
  }, [prefs.clipboardClearSeconds]);

  // Idle lock mirrors the TUI; a heartbeat keeps the server session alive while the user is active.
  useEffect(() => {
    const mark = () => {
      lastActivity.current = Date.now();
    };
    for (const event of ACTIVITY_EVENTS) window.addEventListener(event, mark, { passive: true });
    const timer = window.setInterval(() => {
      const now = Date.now();
      const idleMs = prefs.idleLockSeconds * 1000;
      if (idleMs > 0 && now - lastActivity.current >= idleMs) {
        lock("Locked after inactivity");
        return;
      }
      if (lastActivity.current > lastBeat.current && now - lastBeat.current >= HEARTBEAT_MS) {
        lastBeat.current = now;
        void api.session().catch((error) => {
          if (errorMessage(error) !== "Locked") toast.error(errorMessage(error));
        });
      }
    }, 5000);
    return () => {
      for (const event of ACTIVITY_EVENTS) window.removeEventListener(event, mark);
      window.clearInterval(timer);
    };
  }, [prefs.idleLockSeconds, lock]);

  // Lock when the hard session cap is reached, even with the tab open.
  useEffect(() => {
    const timer = window.setTimeout(() => lock("Session expired — unlock again"), Math.max(0, session.hardAt - Date.now()));
    return () => window.clearTimeout(timer);
  }, [session.hardAt, lock]);

  useEffect(() => () => {
    if (clipboardTimer.current !== null) window.clearTimeout(clipboardTimer.current);
  }, []);

  const value = useMemo<AppValue>(() => ({
    session, prefs, setPrefs, screen, go, vaultGroup, openGroup, lock, copy,
    setScreenCommands, screenCommands, setHints, hints, paletteOpen, setPaletteOpen, modalOpen, setModalOpen,
  }), [session, prefs, screen, go, vaultGroup, openGroup, lock, copy, screenCommands, hints, paletteOpen, modalOpen]);

  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
}
