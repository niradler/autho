import { createContext, useContext, useEffect, useRef } from "react";

import type { KeyEvent } from "@opentui/core";

import type { CopyResult } from "../clipboard.ts";

export type Timings = { revealMs: number; clipboardClearMs: number; idleLockMs: number };

export type ToastKind ="success" | "error" | "info";
export type Toast = { message: string; kind: ToastKind };

export type Command = {
  id: string;
  title: string;
  /** Shortcut shown in the palette, purely informational. */
  hint?: string;
  group: string;
  run: () => void;
};

/** Top-level pages, shown as header tabs once the vault is unlocked. */
export type Page = "vault" | "leases" | "audit" | "integrity" | "settings";

export const PAGES: { page: Page; label: string; key: string }[] = [
  { page: "vault", label: "Vault", key: "1" },
  { page: "leases", label: "Leases", key: "2" },
  { page: "audit", label: "Audit", key: "3" },
  { page: "integrity", label: "Integrity", key: "4" },
  { page: "settings", label: "Settings", key: "5" },
];

/** What Ctrl+C copies when nothing is selected with the mouse. */
export type CopyTarget = { label: string; read: () => string | null; secret: boolean };

export type AppApi = {
  /** False while an overlay (palette, confirm) owns the keyboard. */
  active: boolean;
  toast: (message: string, kind?: ToastKind) => void;
  copy: (label: string, text: string, options?: { secret?: boolean }) => Promise<CopyResult>;
  lock: () => void;
  quit: () => void;
  openPalette: () => void;
  /** Switches to a top-level page. */
  go: (page: Page) => void;
  /** Applies changed TUI timings from Settings without a restart. */
  setTimings: (next: Partial<Timings>) => void;
  /** Screens publish contextual palette commands and the Ctrl+C copy target. */
  commandsRef: { current: Command[] };
  copyTargetRef: { current: CopyTarget | null };
};

export const AppContext = createContext<AppApi | null>(null);

export function useApp(): AppApi {
  const api = useContext(AppContext);
  if (!api) {
    throw new Error("useApp must be used inside <AppContext.Provider>");
  }
  return api;
}

/** Registers the current screen's palette commands and Ctrl+C target. */
export function useScreenContext(commands: Command[], copyTarget: CopyTarget | null): void {
  const app = useApp();
  const latest = useRef({ commands, copyTarget });
  latest.current = { commands, copyTarget };
  app.commandsRef.current = commands;
  app.copyTargetRef.current = copyTarget;
  useEffect(() => () => {
    if (app.commandsRef.current === latest.current.commands) {
      app.commandsRef.current = [];
    }
    if (app.copyTargetRef.current === latest.current.copyTarget) {
      app.copyTargetRef.current = null;
    }
  }, [app]);
}

/**
 * Page keys (1-5). Screens call this only while no field has the
 * keyboard, so the keys still type into inputs.
 */
export function handlePageKey(app: AppApi, key: KeyEvent): boolean {
  if (key.ctrl || key.meta || key.shift) return false;
  const target = PAGES.find((p) => p.key === key.name || p.key === key.sequence);
  if (!target) return false;
  key.preventDefault();
  app.go(target.page);
  return true;
}

export function describeCopy(label: string, result: CopyResult, clearSeconds: number | null): Toast {
  if (!result.ok) {
    return { kind: "error", message: result.error };
  }
  const via = result.method === "osc52" ? " (via terminal)" : "";
  const clear = clearSeconds ? ` · clears in ${clearSeconds}s` : "";
  return { kind: "success", message: `${label} copied${via}${clear}` };
}
