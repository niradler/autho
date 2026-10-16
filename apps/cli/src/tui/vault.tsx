import { useKeyboard, useTerminalDimensions } from "@opentui/react";
import { useCallback, useEffect, useMemo, useState } from "react";

import type { SecretIndexEntry, VaultSession } from "../../../../packages/core/src/index.ts";
import { Button, FieldRow, TextField, useNow, type KeyHint } from "./components.tsx";
import { useApp, useScreenContext, type Command } from "./context.tsx";
import { MASK, TIMINGS, theme, typeBadge, typeLabel } from "./theme.ts";
import { fuzzyFilter, hostOf, isEnter, openUrl, truncate } from "./util.ts";

type Revealed = { id: string; value: string; until: number };
type Otp = { id: string; code: string; expiresAt: number };

/** Wide terminals get a list + preview layout; narrow ones switch between the two. */
const WIDE_MIN_COLUMNS = 96;

export function VaultScreen({ session, initialSelectedId, onCreate, onEdit, setHints, revealMs }: {
  session: VaultSession;
  /** Secret to select on mount, e.g. the one just created or edited. */
  initialSelectedId?: string;
  onCreate: () => void;
  onEdit: (id: string) => void;
  setHints: (hints: KeyHint[]) => void;
  revealMs: number;
}) {
  const app = useApp();
  const { width, height } = useTerminalDimensions();
  const wide = width >= WIDE_MIN_COLUMNS;

  const [entries, setEntries] = useState<SecretIndexEntry[]>([]);
  const [query, setQuery] = useState("");
  const [searchFocused, setSearchFocused] = useState(false);
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

  useKeyboard((key) => {
    if (!app.active || key.ctrl || key.meta) return;

    if (confirmDelete) {
      key.preventDefault();
      if ((key.name === "y" || isEnter(key)) && selected) remove(selected);
      else if (key.name === "n" || key.name === "escape") setConfirmDelete(false);
      return;
    }

    if (searchFocused) {
      if (key.name === "escape") { setQuery(""); setSearchFocused(false); }
      else if (isEnter(key) || key.name === "down" || key.name === "tab") { key.preventDefault(); setSearchFocused(false); }
      return;
    }

    switch (key.name) {
      case "up": case "k": move(-1); return;
      case "down": case "j": move(1); return;
      case "pageup": move(-listHeight); return;
      case "pagedown": move(listHeight); return;
      case "home": case "g": move(-filtered.length); return;
      case "end": move(filtered.length); return;
      case "/": key.preventDefault(); setSearchFocused(true); return;
      case "n": onCreate(); return;
      case "q": app.quit(); return;
      case "?": app.openPalette(); return;
      case "r": reload(); app.toast("Reloaded", "info"); return;
    }
    if (key.sequence === "G") { move(filtered.length); return; }
    if (!selected) return;

    if (isEnter(key)) {
      if (!showDetail) setDetailOpen(true);
      else copyPrimary(selected);
      return;
    }
    switch (key.name) {
      case "right": case "l": setDetailOpen(true); return;
      case "left": case "h": case "escape":
        if (detailOpen && !wide) setDetailOpen(false);
        else if (revealed) setRevealed(null);
        else if (query) setQuery("");
        return;
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
      { id: "search", title: "Search secrets", hint: "/", group: "Vault", run: () => setSearchFocused(true) },
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
        run: () => { setQuery(""); setSelectedId(entry.id); setDetailOpen(true); },
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
    else if (!showDetail) hints = [["↑↓", "move"], ["enter", "open"], ["c", "copy"], ["u", "user"], ["/", "search"], ["n", "new"], ["ctrl+k", "commands"], ["q", "quit"]];
    else hints = [["enter/c", "copy"], ["u", "user"], ["s", "reveal"], ...(selected?.type === "otp" ? [["o", "code"] as KeyHint] : []), ["e", "edit"], ["d", "delete"], ["/", "search"], ["ctrl+k", "commands"], wide ? ["q", "quit"] : ["esc", "back"]];
    setHints(hints);
  }, [confirmDelete, searchFocused, showDetail, wide, selected?.type, setHints]);

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
      borderColor={showDetail && !wide ? theme.border : theme.borderFocus}
      title={` ${filtered.length}/${entries.length} secrets `}
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
            onMouseDown={() => { setSelectedId(entry.id); if (!wide) setDetailOpen(true); }}
          >
            <text>
              <span fg={badge.color}>{badge.glyph} </span>
              <span fg={isSelected ? "#FFFFFF" : theme.text}>{name}</span>
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
      onCopy={() => copyPrimary(selected)}
      onCopyUser={() => copyUsername(selected)}
      onCopyUrl={() => copyUrl(selected)}
      onReveal={() => toggleReveal(selected)}
      onOtp={() => copyPrimary(selected)}
    />
  ) : (
    <box flexGrow={1} border borderStyle="rounded" borderColor={theme.border} padding={1}>
      <text fg={theme.dim}>Nothing selected.</text>
    </box>
  );

  return (
    <box flexDirection="column" flexGrow={1} width="100%">
      <box flexDirection="row" paddingX={1} height={1} gap={1}>
        <text fg={searchFocused ? theme.accent : theme.dim}>/</text>
        <TextField value={query} onChange={setQuery} focused={searchFocused && app.active} placeholder="search by name, username, url…" />
      </box>
      <box flexDirection="row" flexGrow={1} gap={1}>
        {wide || !detailOpen ? list : null}
        {showDetail ? detail : null}
      </box>
    </box>
  );
}

function Detail({ entry, revealed, otp, now, confirmDelete, onCopy, onCopyUser, onCopyUrl, onReveal, onOtp }: {
  entry: SecretIndexEntry;
  revealed: Revealed | null;
  otp: Otp | null;
  now: number;
  confirmDelete: boolean;
  onCopy: () => void;
  onCopyUser: () => void;
  onCopyUrl: () => void;
  onReveal: () => void;
  onOtp: () => void;
}) {
  const badge = typeBadge(entry.type);
  const valueLabel = entry.type === "note" ? "Note" : entry.type === "otp" ? "Secret key" : "Password";
  const revealSeconds = revealed ? Math.max(0, Math.ceil((revealed.until - now) / 1000)) : 0;
  const otpSeconds = otp ? Math.max(0, Math.ceil((otp.expiresAt - now) / 1000)) : 0;

  return (
    <box flexDirection="column" flexGrow={1} border borderStyle="rounded" borderColor={confirmDelete ? theme.danger : theme.border} paddingX={1} gap={1} title={` ${typeLabel(entry.type)} `}>
      <text><span fg={badge.color}>{badge.glyph} </span><strong fg={theme.accent}>{entry.name}</strong></text>

      <box flexDirection="column">
        {entry.type !== "note" ? (
          <FieldRow
            label="Username"
            value={entry.username ?? "—"}
            color={entry.username ? theme.text : theme.dim}
            actions={entry.username ? <Button label="copy · u" onPress={onCopyUser} /> : null}
          />
        ) : null}
        <FieldRow
          label={valueLabel}
          value={revealed ? revealed.value : MASK}
          color={revealed ? theme.revealed : theme.muted}
          actions={<>
            <Button label={revealed ? "hide · s" : "reveal · s"} onPress={onReveal} color={theme.info} />
            {entry.type !== "otp" ? <Button label="copy · c" onPress={onCopy} /> : null}
          </>}
        />
        {entry.type === "otp" ? (
          <FieldRow
            label="Code"
            value={otp ? `${otp.code.slice(0, 3)} ${otp.code.slice(3)}` : "press o to show"}
            color={otp ? theme.success : theme.dim}
            actions={<>
              {otp ? <text fg={otpSeconds <= 5 ? theme.danger : theme.dim}>{otpSeconds}s</text> : null}
              <Button label="copy · o" onPress={onOtp} />
            </>}
          />
        ) : null}
        {entry.url ? <FieldRow label="URL" value={entry.url} color={theme.info} actions={<Button label="copy · w" onPress={onCopyUrl} />} /> : null}
        {entry.description ? <FieldRow label="Notes" value={entry.description} /> : null}
        <FieldRow label="Updated" value={entry.updatedAt.slice(0, 16).replace("T", " ")} color={theme.dim} />
      </box>

      {revealed ? (
        <text fg={theme.dim}>Visible for {revealSeconds}s — drag to select, ctrl+c to copy the selection.</text>
      ) : null}
      {confirmDelete ? (
        <box border borderStyle="rounded" borderColor={theme.danger} paddingX={1}>
          <text fg={theme.danger}><strong>Delete "{entry.name}" permanently?</strong><span fg={theme.muted}>  y = delete · n = cancel</span></text>
        </box>
      ) : null}
    </box>
  );
}
