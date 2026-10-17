import { useKeyboard, useTerminalDimensions } from "@opentui/react";
import { useCallback, useEffect, useMemo, useState } from "react";

import type { SecretIndexEntry, VaultSession } from "../../../../packages/core/src/index.ts";
import { Button, FieldRow, TextField, useNow, type KeyHint } from "./components.tsx";
import { useApp, useScreenContext, type Command } from "./context.tsx";
import { MASK, TIMINGS, theme, typeBadge, typeLabel } from "./theme.ts";
import { fuzzyFilter, hostOf, isEnter, openUrl, truncate } from "./util.ts";

type Revealed = { id: string; value: string; until: number };
type Otp = { id: string; code: string; expiresAt: number };
/** Where arrows and enter act. Tab / shift+tab cycle search → list → actions. */
type Pane = "search" | "list" | "actions";
type Action = { id: string; hotkey: string; label: string; color: string; run: () => void };

const PANES: Pane[] = ["search", "list", "actions"];

/** Wide terminals get a list + preview layout; narrow ones switch between the two. */
const WIDE_MIN_COLUMNS = 96;

export function VaultScreen({ session, initialSelectedId, onCreate, onEdit, onSettings, setHints, revealMs }: {
  session: VaultSession;
  /** Secret to select on mount, e.g. the one just created or edited. */
  initialSelectedId?: string;
  onCreate: () => void;
  onEdit: (id: string) => void;
  onSettings: () => void;
  setHints: (hints: KeyHint[]) => void;
  revealMs: number;
}) {
  const app = useApp();
  const { width, height } = useTerminalDimensions();
  const wide = width >= WIDE_MIN_COLUMNS;

  const [entries, setEntries] = useState<SecretIndexEntry[]>([]);
  const [query, setQuery] = useState("");
  const [pane, setPane] = useState<Pane>("list");
  const [actionIndex, setActionIndex] = useState(0);
  const searchFocused = pane === "search";
  const [selectedId, setSelectedId] = useState<string | null>(initialSelectedId ?? null);
  const [detailOpen, setDetailOpen] = useState(false);
  const [revealed, setRevealed] = useState<Revealed | null>(null);
  const [otp, setOtp] = useState<Otp | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);

  const reload = useCallback(() => {
    try {
      setEntries(session.listSecretIndex());
    } catch (e) {
      app.toast(e instanceof Error ? e.message : String(e), "error");
      setEntries([]);
    }
  }, [session, app]);

  useEffect(reload, [reload]);

  const filtered = useMemo(
    () => fuzzyFilter(entries, query, (e) => [e.name, e.username, e.url, e.description, typeLabel(e.type)]),
    [entries, query],
  );

  const selectedIndex = Math.max(0, filtered.findIndex((e) => e.id === selectedId));
  const selected: SecretIndexEntry | null = filtered[selectedIndex] ?? null;

  // Keep a valid selection as the filter changes.
  useEffect(() => {
    if (filtered.length > 0 && (!selectedId || !filtered.some((e) => e.id === selectedId))) {
      setSelectedId(filtered[0]!.id);
    }
  }, [filtered, selectedId]);

  // Revealed values and OTP codes belong to one secret; drop them when the selection moves.
  useEffect(() => {
    setRevealed((r) => (r && r.id !== selected?.id ? null : r));
    setOtp((o) => (o && o.id !== selected?.id ? null : o));
    setConfirmDelete(false);
    setActionIndex(0);
  }, [selected?.id]);

  const now = useNow(1000, Boolean(revealed || otp));

  useEffect(() => {
    if (revealed && now >= revealed.until) {
      setRevealed(null);
    }
  }, [now, revealed]);

  const readValue = useCallback((entry: SecretIndexEntry): string | null => {
    try {
      return session.getSecret(entry.id).value;
    } catch (e) {
      app.toast(e instanceof Error ? e.message : String(e), "error");
      return null;
    }
  }, [session, app]);

  const generateOtp = useCallback((entry: SecretIndexEntry): Otp | null => {
    try {
      const result = session.generateOtp(entry.id);
      const next = { id: entry.id, code: result.code, expiresAt: Date.parse(result.expiresAt) };
      setOtp(next);
      return next;
    } catch (e) {
      app.toast(e instanceof Error ? e.message : String(e), "error");
      return null;
    }
  }, [session, app]);

  // Keep a shown OTP code current while its secret stays selected.
  useEffect(() => {
    if (otp && selected && otp.id === selected.id && now >= otp.expiresAt) {
      generateOtp(selected);
    }
  }, [now, otp, selected, generateOtp]);

  const copyPrimary = useCallback((entry: SecretIndexEntry | null) => {
    if (!entry) return;
    if (entry.type === "otp") {
      const code = generateOtp(entry);
      if (code) void app.copy("OTP code", code.code, { secret: true });
      return;
    }
    const value = readValue(entry);
    if (value !== null) {
      void app.copy(entry.type === "note" ? "Note" : "Password", value, { secret: true });
    }
  }, [app, generateOtp, readValue]);

  const copyUsername = useCallback((entry: SecretIndexEntry | null) => {
    if (!entry) return;
    if (!entry.username) {
      app.toast(`${entry.name} has no username`, "info");
      return;
    }
    void app.copy("Username", entry.username);
  }, [app]);

  const copyUrl = useCallback((entry: SecretIndexEntry | null) => {
    if (!entry?.url) {
      app.toast("No URL on this secret", "info");
      return;
    }
    void app.copy("URL", entry.url);
  }, [app]);

  const toggleReveal = useCallback((entry: SecretIndexEntry | null) => {
    if (!entry) return;
    if (revealed?.id === entry.id) {
      setRevealed(null);
      return;
    }
    const value = readValue(entry);
    if (value !== null) {
      setRevealed({ id: entry.id, value, until: Date.now() + revealMs });
    }
  }, [revealed, readValue, revealMs]);

  const remove = useCallback((entry: SecretIndexEntry) => {
    try {
      session.removeSecret(entry.id);
      app.toast(`Deleted "${entry.name}"`);
      setConfirmDelete(false);
      setDetailOpen(false);
      setPane("list");
      reload();
    } catch (e) {
      app.toast(e instanceof Error ? e.message : String(e), "error");
    }
  }, [session, app, reload]);

  const open = (entry: SecretIndexEntry | null) => {
    if (!entry?.url) {
      app.toast("No URL on this secret", "info");
      return;
    }
    const opened = openUrl(entry.url);
    app.toast(opened ? `Opening ${hostOf(entry.url)}` : "Only http(s) URLs can be opened", opened ? "info" : "error");
  };

  const move = (delta: number) => {
    if (filtered.length === 0) return;
    const next = Math.min(filtered.length - 1, Math.max(0, selectedIndex + delta));
    setSelectedId(filtered[next]!.id);
  };

  const showDetail = wide || detailOpen;
  const listHeight = Math.max(3, height - 6);

  const actions: Action[] = selected ? [
    selected.type === "otp"
      ? { id: "copy", hotkey: "o", label: "copy code", color: theme.success, run: () => copyPrimary(selected) }
      : { id: "copy", hotkey: "c", label: `copy ${valueName(selected.type).toLowerCase()}`, color: theme.success, run: () => copyPrimary(selected) },
    ...(selected.url && selected.type !== "otp" ? [{ id: "open", hotkey: "o", label: "open", color: theme.info, run: () => open(selected) }] : []),
    { id: "edit", hotkey: "e", label: "edit", color: theme.accent, run: () => onEdit(selected.id) },
    { id: "delete", hotkey: "d", label: "delete", color: theme.danger, run: () => setConfirmDelete(true) },
  ] : [];
  const currentAction = Math.min(actionIndex, Math.max(0, actions.length - 1));

  /** Moves focus to another pane; the action row needs a selection to land on. */
  const focusPane = (next: Pane) => {
    if (next === "actions") {
      if (!selected) return;
      setDetailOpen(true);
      setActionIndex(0);
    }
    if (next !== "actions" && !wide) setDetailOpen(false);
    setPane(next);
  };

  const cyclePane = (delta: number) => {
    let index = PANES.indexOf(pane);
    do index = (index + delta + PANES.length) % PANES.length;
    while (PANES[index] === "actions" && !selected);
    focusPane(PANES[index]!);
  };

  useKeyboard((key) => {
    if (!app.active || key.ctrl || key.meta) return;

    if (confirmDelete) {
      key.preventDefault();
      if ((key.name === "y" || isEnter(key)) && selected) remove(selected);
      else if (key.name === "n" || key.name === "escape") setConfirmDelete(false);
      return;
    }

    if (key.name === "tab") { key.preventDefault(); cyclePane(key.shift ? -1 : 1); return; }

    if (searchFocused) {
      if (key.name === "escape") { setQuery(""); setPane("list"); }
      else if (isEnter(key) || key.name === "down") { key.preventDefault(); setPane("list"); }
      return;
    }

    switch (key.name) {
      case "up": case "k": move(-1); return;
      case "down": case "j": move(1); return;
      case "pageup": move(-listHeight); return;
      case "pagedown": move(listHeight); return;
      // Terminals report Shift+G as name "g" with shift set.
      case "g": move(key.shift ? filtered.length : -filtered.length); return;
      case "home": move(-filtered.length); return;
      case "end": move(filtered.length); return;
      case "/": key.preventDefault(); focusPane("search"); return;
      case "n": onCreate(); return;
      case "q": app.quit(); return;
      case "?": app.openPalette(); return;
      case ",": onSettings(); return;
      case "r": reload(); app.toast("Reloaded", "info"); return;
    }

    // Esc steps back one level: actions → list, then hides a revealed value, then clears the filter.
    if (key.name === "escape") {
      if (pane === "actions") focusPane("list");
      else if (revealed) setRevealed(null);
      else if (query) setQuery("");
      return;
    }
    if (!selected) return;

    if (pane === "actions") {
      switch (key.name) {
        // Functional updates: key repeat can land several presses before a re-render.
        case "left": case "h":
          if (currentAction === 0) focusPane("list");
          else setActionIndex((i) => Math.max(0, Math.min(i, actions.length - 1) - 1));
          return;
        case "right": case "l": setActionIndex((i) => Math.min(actions.length - 1, i + 1)); return;
        case "space": actions[currentAction]?.run(); return;
      }
      if (isEnter(key)) { actions[currentAction]?.run(); return; }
    } else {
      if (key.name === "right" || key.name === "l") { focusPane("actions"); return; }
      if (isEnter(key)) {
        // Wide: the detail is already on screen, so enter is the quick copy. Narrow: open it.
        if (showDetail) copyPrimary(selected);
        else focusPane("actions");
        return;
      }
    }
    switch (key.name) {
      case "c": copyPrimary(selected); return;
      case "u": copyUsername(selected); return;
      case "w": copyUrl(selected); return;
      case "s": case "space": toggleReveal(selected); return;
      case "o":
        if (selected.type === "otp") copyPrimary(selected);
        else open(selected);
        return;
      case "e": onEdit(selected.id); return;
      case "d": case "delete": setConfirmDelete(true); return;
    }
  });

  const commands = useMemo<Command[]>(() => {
    const list: Command[] = [
      { id: "new", title: "New secret", hint: "n", group: "Vault", run: onCreate },
      { id: "search", title: "Search secrets", hint: "/", group: "Vault", run: () => setPane("search") },
      { id: "reload", title: "Reload list", hint: "r", group: "Vault", run: reload },
    ];
    if (selected) {
      const name = selected.name;
      list.unshift(
        { id: "copy", title: `Copy ${selected.type === "otp" ? "OTP code" : selected.type === "note" ? "note" : "password"} — ${name}`, hint: "c / enter", group: "Selected", run: () => copyPrimary(selected) },
        { id: "copy-user", title: `Copy username — ${name}`, hint: "u", group: "Selected", run: () => copyUsername(selected) },
        { id: "reveal", title: `${revealed ? "Hide" : "Reveal"} value — ${name}`, hint: "s", group: "Selected", run: () => toggleReveal(selected) },
        { id: "edit", title: `Edit — ${name}`, hint: "e", group: "Selected", run: () => onEdit(selected.id) },
        { id: "delete", title: `Delete — ${name}`, hint: "d", group: "Selected", run: () => setConfirmDelete(true) },
      );
      if (selected.url) {
        list.splice(2, 0,
          { id: "copy-url", title: `Copy URL — ${name}`, hint: "w", group: "Selected", run: () => copyUrl(selected) },
          { id: "open-url", title: `Open ${hostOf(selected.url)} in browser`, hint: selected.type === "otp" ? undefined : "o", group: "Selected", run: () => open(selected) });
      }
    }
    for (const entry of entries) {
      list.push({
        id: `goto:${entry.id}`,
        title: entry.name,
        hint: entry.username ?? (entry.url ? hostOf(entry.url) : typeLabel(entry.type)),
        group: "Jump to",
        run: () => { setQuery(""); setSelectedId(entry.id); setDetailOpen(true); setPane("actions"); },
      });
    }
    return list;
  }, [entries, selected, revealed, onCreate, onEdit, reload, copyPrimary, copyUsername, copyUrl, toggleReveal]);

  useScreenContext(commands, selected ? {
    label: selected.type === "otp" ? "OTP code" : selected.type === "note" ? "Note" : "Password",
    read: () => selected.type === "otp" ? (generateOtp(selected)?.code ?? null) : readValue(selected),
    secret: true,
  } : null);

  useEffect(() => {
    let hints: KeyHint[];
    if (confirmDelete) hints = [["y", "delete"], ["n/esc", "cancel"]];
    else if (searchFocused) hints = [["type", "filter"], ["enter/↓", "results"], ["esc", "clear"]];
    else if (pane === "actions") hints = [["←→", "choose"], ["enter", "run"], ["↑↓", "secret"], ["esc", "back"]];
    else if (!showDetail) hints = [["↑↓", "move"], ["enter", "open"], ["c", "copy"], ["/", "search"], ["n", "new"], ["q", "quit"]];
    else hints = [["↑↓", "move"], ["enter", "copy"], ["→/tab", "actions"], ["/", "search"], ["n", "new"], ["q", "quit"]];
    setHints(hints);
  }, [confirmDelete, searchFocused, pane, showDetail, setHints]);

  const listWidth = wide ? Math.max(32, Math.floor(width * 0.38)) : width;
  const offset = Math.max(0, Math.min(selectedIndex - Math.floor(listHeight / 2), filtered.length - listHeight));
  const visible = filtered.slice(offset, offset + listHeight);

  const list = (
    <box
      flexDirection="column"
      width={wide ? listWidth : "100%"}
      flexShrink={0}
      border
      borderStyle="rounded"
      borderColor={theme.border}
      title={` ${filtered.length}/${entries.length} secrets `}
      titleColor={theme.muted}
      onMouseScroll={(event) => move(event.scroll?.direction === "up" ? -3 : 3)}
    >
      {filtered.length === 0 ? (
        <box padding={1}>
          <text fg={theme.dim}>{entries.length === 0 ? "No secrets yet — press n to add one." : `No match for "${query}".`}</text>
        </box>
      ) : visible.map((entry) => {
        const isSelected = entry.id === selected?.id;
        const badge = typeBadge(entry.type);
        const sub = entry.username ?? (entry.url ? hostOf(entry.url) : "");
        const room = listWidth - 6;
        const name = truncate(entry.name, Math.max(8, Math.min(room, Math.ceil(room * 0.55))));
        return (
          <box
            key={entry.id}
            flexDirection="row"
            height={1}
            paddingX={1}
            backgroundColor={isSelected ? theme.selection : undefined}
            onMouseDown={() => { setSelectedId(entry.id); if (wide) setPane("list"); else { setDetailOpen(true); setPane("actions"); } }}
          >
            <text>
              <span fg={badge.color}>{badge.glyph} </span>
              {isSelected ? <strong fg={theme.accent}>{name}</strong> : <span fg={theme.text}>{name}</span>}
              <span fg={theme.dim}>{sub ? `  ${truncate(sub, Math.max(0, room - name.length - 2))}` : ""}</span>
            </text>
          </box>
        );
      })}
    </box>
  );

  const detail = selected ? (
    <Detail
      entry={selected}
      revealed={revealed?.id === selected.id ? revealed : null}
      otp={otp?.id === selected.id ? otp : null}
      now={now}
      confirmDelete={confirmDelete}
      actions={actions}
      focusedAction={pane === "actions" ? currentAction : null}
    />
  ) : (
    <box flexGrow={1} border borderStyle="rounded" borderColor={theme.border} padding={1}>
      <text fg={theme.dim}>Nothing selected.</text>
    </box>
  );

  return (
    <box flexDirection="column" flexGrow={1} width="100%">
      <box flexDirection="row" paddingX={1} height={1}>
        <text bg={searchFocused ? theme.accent : theme.chip} fg={searchFocused ? theme.onAccent : theme.muted}> / </text>
        <TextField value={query} onChange={setQuery} focused={searchFocused && app.active} placeholder="search by name, username, url…" />
      </box>
      <box flexDirection="row" flexGrow={1} gap={1}>
        {wide || !detailOpen ? list : null}
        {showDetail ? detail : null}
      </box>
    </box>
  );
}

function valueName(type: string): string {
  return type === "note" ? "Note" : type === "otp" ? "Secret key" : "Password";
}

function Detail({ entry, revealed, otp, now, confirmDelete, actions, focusedAction }: {
  entry: SecretIndexEntry;
  revealed: Revealed | null;
  otp: Otp | null;
  now: number;
  confirmDelete: boolean;
  actions: Action[];
  /** Index of the keyboard-focused action, or null when focus is elsewhere. */
  focusedAction: number | null;
}) {
  const badge = typeBadge(entry.type);
  const valueLabel = valueName(entry.type);
  const revealSeconds = revealed ? Math.max(0, Math.ceil((revealed.until - now) / 1000)) : 0;
  const otpSeconds = otp ? Math.max(0, Math.ceil((otp.expiresAt - now) / 1000)) : 0;
  const otpBar = 10;
  const otpFilled = Math.round((otpSeconds / 30) * otpBar);

  return (
    <box flexDirection="column" flexGrow={1} border borderStyle="rounded" borderColor={confirmDelete ? theme.danger : theme.border} paddingX={1} gap={1} title={` ${typeLabel(entry.type)} `} titleColor={badge.color}>
      <text><span fg={badge.color}>{badge.glyph} </span><strong fg={theme.accent}>{entry.name}</strong></text>

      <box flexDirection="column">
        {entry.type !== "note" ? (
          <FieldRow
            label="Username"
            value={entry.username ?? "—"}
            color={entry.username ? theme.text : theme.dim}
          />
        ) : null}
        <FieldRow
          label={valueLabel}
          value={revealed ? revealed.value : MASK}
          color={revealed ? theme.revealed : theme.dim}
        />
        {entry.url ? <FieldRow label="URL" value={entry.url} color={theme.info} /> : null}
        {entry.description ? <FieldRow label="Notes" value={entry.description} /> : null}
        <FieldRow label="Updated" value={entry.updatedAt.slice(0, 16).replace("T", " ")} color={theme.dim} />
      </box>

      {entry.type === "otp" ? (
        <box flexDirection="row" border borderStyle="rounded" borderColor={otp ? theme.success : theme.border} paddingX={1} gap={2} alignSelf="flex-start">
          {otp ? (
            <>
              <text fg={theme.success} selectable><strong>{`${otp.code.slice(0, 3)} ${otp.code.slice(3)}`}</strong></text>
              <text><span fg={otpSeconds <= 5 ? theme.danger : theme.success}>{"█".repeat(otpFilled)}</span><span fg={theme.chip}>{"█".repeat(otpBar - otpFilled)}</span><span fg={otpSeconds <= 5 ? theme.danger : theme.muted}> {otpSeconds}s</span></text>
            </>
          ) : <text fg={theme.dim}>press o to show the code</text>}
        </box>
      ) : null}

      {revealed ? (
        <text fg={theme.dim}>Visible for {revealSeconds}s — drag to select, ctrl+c to copy the selection.</text>
      ) : null}

      {confirmDelete ? (
        <box backgroundColor={theme.dangerBg} paddingX={1}>
          <text fg={theme.danger}><strong>Delete "{entry.name}" permanently?</strong><span fg={theme.muted}>  y = delete · n = cancel</span></text>
        </box>
      ) : (
        <box flexDirection="row" gap={1} flexWrap="wrap">
          {actions.map((action, i) => (
            <Button key={action.id} hotkey={action.hotkey} label={action.label} onPress={action.run} color={action.color} focused={focusedAction === i} />
          ))}
        </box>
      )}
    </box>
  );
}
