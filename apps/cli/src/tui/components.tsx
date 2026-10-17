import { decodePasteBytes } from "@opentui/core";
import { useKeyboard, usePaste, useTerminalDimensions } from "@opentui/react";
import { useEffect, useRef, useState, type ReactNode } from "react";

import type { Toast } from "./context.tsx";
import { theme } from "./theme.ts";
import { cleanPaste, isEnter, typedText } from "./util.ts";

export function Header({ title, right }: { title: string; right?: ReactNode }) {
  return (
    <box width="100%" height={2} flexDirection="row" paddingX={1} justifyContent="space-between" border={["bottom"]} borderColor={theme.border}>
      <text><span bg={theme.accent} fg={theme.onAccent}><strong> autho </strong></span><span fg={theme.dim}>  </span><strong fg={theme.text}>{title}</strong></text>
      {right ?? null}
    </box>
  );
}

/** A key shown as a small raised chip, e.g. in hints and buttons. */
export function Chip({ label, color = theme.accent }: { label: string; color?: string }) {
  return <span bg={theme.chip} fg={color}> {label} </span>;
}

export type KeyHint = [key: string, label: string];

/** Bottom bar: shows the latest toast, otherwise the key hints for the screen. */
export function StatusBar({ hints, toast }: { hints: KeyHint[]; toast: Toast | null }) {
  const { width } = useTerminalDimensions();
  if (toast) {
    const color = toast.kind === "error" ? theme.danger : toast.kind === "info" ? theme.info : theme.success;
    const icon = toast.kind === "error" ? "✗" : toast.kind === "info" ? "›" : "✓";
    return (
      <box width="100%" height={1} backgroundColor={color} paddingX={1}>
        <text fg={theme.onAccent}><strong>{icon} {toast.message}</strong></text>
      </box>
    );
  }
  return (
    <box width="100%" height={1} backgroundColor={theme.panel} paddingX={1} flexDirection="row" gap={2} overflow="hidden">
      {fitHints(hints, width - 2).map(([key, label]) => (
        <text key={`${key}-${label}`} flexShrink={0}><Chip label={key} /><span fg={theme.muted}> {label}</span></text>
      ))}
    </box>
  );
}

/** Clickable action; `hotkey` renders as a coloured key cap in front of the label. */
/** Drops trailing hints that would not fit, instead of cutting one in half. */
function fitHints(hints: KeyHint[], width: number): KeyHint[] {
  const shown: KeyHint[] = [];
  let used = 0;
  for (const hint of hints) {
    // " key " chip + " label" + gap of 2.
    const size = hint[0].length + 2 + 1 + hint[1].length + (shown.length ? 2 : 0);
    if (used + size > width) break;
    shown.push(hint);
    used += size;
  }
  return shown;
}

export function Button({ label, hotkey, onPress, color = theme.accent }: { label: string; hotkey?: string; onPress: () => void; color?: string }) {
  return (
    <box onMouseDown={(event) => { event.preventDefault(); onPress(); }} height={1} flexShrink={0}>
      <text>{hotkey ? <span bg={color} fg={theme.onAccent}><strong> {hotkey} </strong></span> : null}<span fg={color}> {label} </span></text>
    </box>
  );
}

/** Label + value row; the value is mouse-selectable so it can be copied with a drag. */
export function FieldRow({ label, value, color = theme.text, actions }: {
  label: string;
  value: string;
  color?: string;
  actions?: ReactNode;
}) {
  return (
    <box flexDirection="row" width="100%" minHeight={1}>
      <text fg={theme.muted} width={12} flexShrink={0}>{label}</text>
      <box flexGrow={1} flexShrink={1}>
        <text fg={color} selectable wrapMode="char">{value}</text>
      </box>
      {actions ? <box flexDirection="row" gap={1} flexShrink={0} marginLeft={1}>{actions}</box> : null}
    </box>
  );
}

/**
 * Masked single-field input for passwords, PINs and secret values.
 *
 * Typed characters show as bullets, bracketed paste works (including
 * Windows Terminal), and Ctrl+R toggles visibility while typing. The value
 * is tracked in a ref so fast typing between renders never drops keys.
 */
export function SecretInput({ value, onChange, onSubmit, focused, placeholder = "", multiline = false, maxLength, visible: shownProp, onToggleVisible }: {
  value: string;
  onChange: (value: string) => void;
  onSubmit?: (value: string) => void;
  focused: boolean;
  placeholder?: string;
  multiline?: boolean;
  maxLength?: number;
  /** Controlled visibility; when omitted the input tracks it itself. */
  visible?: boolean;
  onToggleVisible?: () => void;
}) {
  const [ownVisible, setOwnVisible] = useState(false);
  const visible = shownProp ?? ownVisible;
  const toggleVisible = onToggleVisible ?? (() => setOwnVisible((v) => !v));
  const current = useRef(value);
  const emitted = useRef(value);
  if (value !== emitted.current) {
    current.current = value;
    emitted.current = value;
  }

  const set = (next: string) => {
    const capped = maxLength ? [...next].slice(0, maxLength).join("") : next;
    current.current = capped;
    emitted.current = capped;
    onChange(capped);
  };

  useKeyboard((key) => {
    if (!focused) {
      return;
    }
    if (key.ctrl && key.name === "r") {
      key.preventDefault();
      toggleVisible();
      return;
    }
    if (key.ctrl && key.name === "u") {
      key.preventDefault();
      set("");
      return;
    }
    if (key.name === "backspace") {
      key.preventDefault();
      set([...current.current].slice(0, -1).join(""));
      return;
    }
    if (isEnter(key)) {
      key.preventDefault();
      onSubmit?.(current.current);
      return;
    }
    const text = typedText(key);
    if (text) {
      key.preventDefault();
      set(current.current + text);
    }
  });

  usePaste((event) => {
    if (!focused) {
      return;
    }
    event.preventDefault();
    set(current.current + cleanPaste(decodePasteBytes(event.bytes), multiline));
  });

  const length = [...value].length;
  const shown = visible ? value.replace(/\n/g, "⏎") : "•".repeat(length);
  return (
    <box flexDirection="row" height={1} flexGrow={1} flexShrink={1} minWidth={0} backgroundColor={focused ? theme.inputFocus : theme.input} paddingX={1}>
      <box flexGrow={1} flexShrink={1} overflow="hidden">
        {length === 0 && !focused
          ? <text fg={theme.dim}>{placeholder}</text>
          : <text fg={visible ? theme.revealed : theme.accent}>{shown}{focused ? <span fg={theme.accent}>▏</span> : ""}{length === 0 ? <span fg={theme.dim}>{placeholder}</span> : ""}</text>}
      </box>
    </box>
  );
}

/** Plain single-line input with consistent styling. */
export function TextField({ value, onChange, onSubmit, focused, placeholder = "" }: {
  value: string;
  onChange: (value: string) => void;
  onSubmit?: (value: string) => void;
  focused: boolean;
  placeholder?: string;
}) {
  return (
    <input
      value={value}
      onInput={onChange}
      onSubmit={(v: unknown) => onSubmit?.(typeof v === "string" ? v : value)}
      focused={focused}
      placeholder={placeholder}
      flexGrow={1}
      backgroundColor={theme.input}
      focusedBackgroundColor={theme.inputFocus}
      textColor={theme.text}
      placeholderColor={theme.dim}
    />
  );
}

/** Re-renders every `intervalMs` while enabled; returns the current time. */
export function useNow(intervalMs: number, enabled = true): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!enabled) return;
    setNow(Date.now());
    const timer = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(timer);
  }, [intervalMs, enabled]);
  return now;
}

export function Centered({ children }: { children: ReactNode }) {
  return (
    <box flexDirection="column" alignItems="center" justifyContent="center" width="100%" flexGrow={1}>
      {children}
    </box>
  );
}
