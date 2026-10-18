import { useKeyboard, useTerminalDimensions } from "@opentui/react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { UNGROUPED_LABEL } from "../../../../packages/core/src/index.ts";
import type { GroupSummary, SecretIndexEntry, VaultSession } from "../../../../packages/core/src/index.ts";
import { Chip, FieldRow, TextField, type KeyHint } from "./components.tsx";
import { handlePageKey, useApp, useScreenContext, type Command, type GroupFilter } from "./context.tsx";
import { theme, typeBadge, typeLabel } from "./theme.ts";
import { formatDate, fuzzyFilter, isEnter, truncate } from "./util.ts";

const WIDE_MIN_COLUMNS = 96;

const message = (e: unknown) => (e instanceof Error ? e.message : String(e));
const plural = (count: number, word: string) => `${count} ${word}${count === 1 ? "" : "s"}`;

/** A row in the groups list: a real group, or the fixed "(ungrouped)" row (id null). */
type Row = { id: string | null; name: string; secretCount: number; createdAt: string | null };

/** Groups: create, rename and delete groups, and open the vault narrowed to one. */
export function GroupsScreen({ session, setHints }: { session: VaultSession; setHints: (hints: KeyHint[]) => void }) {
  const app = useApp();
  const { width, height } = useTerminalDimensions();
  const wide = width >= WIDE_MIN_COLUMNS;
  const [groups, setGroups] = useState<GroupSummary[]>([]);
  const [entries, setEntries] = useState<SecretIndexEntry[]>([]);
  const [query, setQuery] = useState("");
  const [searching, setSearching] = useState(false);
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [detailOpen, setDetailOpen] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  /** The name prompt: creating a group, or renaming the selected one. */
  const [naming, setNaming] = useState<{ mode: "create" } | { mode: "rename"; group: GroupSummary } | null>(null);
  const [addingSecrets, setAddingSecrets] = useState(false);

  const reload = useCallback(() => {
    try {
      setGroups(session.listGroups());
      setEntries(session.listSecretIndex());
    } catch (e) {
      app.toast(message(e), "error");
    }
  }, [session, app]);

  useEffect(reload, [reload]);

  const rows = useMemo<Row[]>(() => {
    const ungrouped = entries.filter((e) => e.groupId === null).length;
    const named = fuzzyFilter(groups, query, (g) => [g.name]).map((g) => ({ createdAt: g.createdAt, id: g.id, name: g.name, secretCount: g.secretCount }));
    const showUngrouped = !query || fuzzyFilter([UNGROUPED_LABEL], query, (s) => [s]).length > 0;
    return showUngrouped ? [...named, { createdAt: null, id: null, name: UNGROUPED_LABEL, secretCount: ungrouped }] : named;
  }, [groups, entries, query]);

  const keyOf = (row: Row) => row.id ?? "";
  const selectedIndex = Math.max(0, rows.findIndex((r) => keyOf(r) === selectedKey));
  const selected = rows[selectedIndex] ?? null;
  const selectedGroup = selected?.id ? groups.find((g) => g.id === selected.id) ?? null : null;
  const members = useMemo(() => (selected ? entries.filter((e) => e.groupId === selected.id) : []), [entries, selected]);
  const showDetail = wide || detailOpen;
  const listHeight = Math.max(3, height - 8);

  // Functional update: wheel ticks and key repeat can land several moves before a re-render.
  const move = (delta: number) => {
    if (rows.length === 0) return;
    setSelectedKey((key) => {
      const index = Math.max(0, rows.findIndex((r) => keyOf(r) === key));
      return keyOf(rows[Math.max(0, Math.min(rows.length - 1, index + delta))]!);
    });
    setConfirmDelete(false);
  };

  const openSelected = () => {
    if (selected) app.openGroup({ id: selected.id, name: selected.name } satisfies GroupFilter);
  };

  const startRename = () => {
    if (!selectedGroup) { app.toast(`${UNGROUPED_LABEL} can't be renamed`, "info"); return; }
    setNaming({ group: selectedGroup, mode: "rename" });
  };

  const startDelete = () => {
    if (!selectedGroup) { app.toast(`${UNGROUPED_LABEL} can't be deleted`, "info"); return; }
    setConfirmDelete(true);
  };

  const remove = () => {
    if (!selectedGroup) return;
    setConfirmDelete(false);
    try {
      const result = session.removeGroup(selectedGroup.id);
      app.toast(`Deleted group "${result.name}" · ${plural(result.ungrouped, "secret")} ungrouped`);
      setSelectedKey(null);
      reload();
    } catch (e) {
      app.toast(message(e), "error");
    }
  };

  const startAddSecrets = () => {
    if (!selectedGroup) { app.toast(`Pick a group to add secrets to`, "info"); return; }
    setAddingSecrets(true);
  };

  /** Puts a secret in the selected group, or takes it out when it is already there. */
  const toggleMember = (entry: SecretIndexEntry) => {
    if (!selectedGroup) return;
    const member = entry.groupId === selectedGroup.id;
    try {
      session.updateSecret(entry.id, { group: member ? null : selectedGroup.id });
      if (member) app.toast(`Removed ${entry.name} from ${selectedGroup.name}`, "info");
      else app.toast(entry.group ? `Moved ${entry.name} from ${entry.group} to ${selectedGroup.name}` : `Added ${entry.name} to ${selectedGroup.name}`, "info");
    } catch (e) {
      app.toast(message(e), "error");
    }
    reload();
  };

  const saveName = (name: string): string | null => {
    if (!naming) return null;
    try {
      const group = naming.mode === "create" ? session.createGroup(name) : session.renameGroup(naming.group.id, name);
      app.toast(naming.mode === "create" ? `Created group "${group.name}"` : `Renamed to "${group.name}"`);
      setNaming(null);
      setQuery("");
      setSelectedKey(group.id);
      reload();
      return null;
    } catch (e) {
      return message(e);
    }
  };

  useKeyboard((key) => {
    if (!app.active || key.ctrl || key.meta || naming || addingSecrets) return;
    if (confirmDelete) {
      key.preventDefault();
      if (key.name === "y" || isEnter(key)) remove();
      else if (key.name === "n" || key.name === "escape") setConfirmDelete(false);
      return;
    }
    if (searching) {
      if (key.name === "escape") { setQuery(""); setSearching(false); }
      else if (isEnter(key) || key.name === "down") { key.preventDefault(); setSearching(false); }
      return;
    }
    if (handlePageKey(app, key)) return;
    switch (key.name) {
      case "up": case "k": move(-1); return;
      case "down": case "j": move(1); return;
      case "pageup": move(-listHeight); return;
      case "pagedown": move(listHeight); return;
      case "home": move(-rows.length); return;
      case "end": move(rows.length); return;
      case "/": key.preventDefault(); setSearching(true); return;
      case "n": setNaming({ mode: "create" }); return;
      case "e": startRename(); return;
      case "a": startAddSecrets(); return;
      case "x": case "d": case "delete": startDelete(); return;
      case "r": reload(); app.toast("Reloaded", "info"); return;
      case "q": app.go("vault"); return;
      case "?": app.openPalette(); return;
      case "escape":
        if (query) setQuery("");
        else if (!wide && detailOpen) setDetailOpen(false);
        else app.go("vault");
        return;
    }
    if (isEnter(key)) openSelected();
    else if (key.name === "right" && !wide && selected) setDetailOpen(true);
  });

  const commands = useMemo<Command[]>(() => [
    { id: "group:new", title: "New group", hint: "n", group: "Groups", run: () => setNaming({ mode: "create" }) },
    { id: "group:reload", title: "Reload groups", hint: "r", group: "Groups", run: () => { reload(); app.toast("Reloaded", "info"); } },
    ...(selected ? [{ id: "group:open", title: `Show secrets in ${selected.name}`, hint: "enter", group: "Selected", run: openSelected }] : []),
    ...(selectedGroup ? [
      { id: "group:add", title: `Add secrets to "${selectedGroup.name}"`, hint: "a", group: "Selected", run: startAddSecrets },
      { id: "group:rename", title: `Rename "${selectedGroup.name}"`, hint: "e", group: "Selected", run: startRename },
      { id: "group:delete", title: `Delete "${selectedGroup.name}"`, hint: "x", group: "Selected", run: startDelete },
    ] : []),
  ], [reload, app, selected, selectedGroup]);
  useScreenContext(commands, selectedGroup ? { label: "Group name", read: () => selectedGroup.name, secret: false } : null);

  useEffect(() => {
    if (naming || addingSecrets) return; // The overlays show their own keys.
    if (confirmDelete) setHints([["y", "delete"], ["n/esc", "cancel"]]);
    else if (searching) setHints([["type", "filter"], ["enter/↓", "results"], ["esc", "clear"]]);
    else setHints([["↑↓", "move"], ["enter", "show secrets"], ["n", "new"], ...(selectedGroup ? [["a", "add secrets"], ["e", "rename"], ["x", "delete"]] as KeyHint[] : []), ["/", "filter"], ["esc", "vault"]]);
  }, [naming, addingSecrets, confirmDelete, searching, selectedGroup, setHints]);

  const listWidth = wide ? Math.max(32, Math.floor(width * 0.38)) : width;
  const offset = Math.max(0, Math.min(selectedIndex - Math.floor(listHeight / 2), rows.length - listHeight));
  const shown = rows.slice(offset, offset + listHeight);

  const list = (
    <box
      flexDirection="column"
      width={wide ? listWidth : "100%"}
      flexShrink={0}
      border
      borderStyle="rounded"
      borderColor={theme.border}
      title={` ${plural(groups.length, "group")} `}
      titleColor={theme.muted}
      onMouseScroll={(event) => move(event.scroll?.direction === "up" ? -3 : 3)}
    >
      {groups.length === 0 && !query ? (
        <box paddingX={1}>
          <text fg={theme.dim}>No groups yet — press n to create one.</text>
        </box>
      ) : null}
      {rows.length === 0 ? (
        <box padding={1}><text fg={theme.dim}>No match for "{query}".</text></box>
      ) : shown.map((row) => {
        const on = selected !== null && keyOf(row) === keyOf(selected);
        const count = String(row.secretCount);
        const name = truncate(row.name, Math.max(6, listWidth - 6 - count.length));
        const color = row.id === null ? theme.muted : theme.text;
        return (
          <box
            key={keyOf(row) || "ungrouped"}
            flexDirection="row"
            height={1}
            paddingX={1}
            justifyContent="space-between"
            backgroundColor={on ? theme.selection : undefined}
            onMouseDown={() => { setSelectedKey(keyOf(row)); setConfirmDelete(false); if (!wide) setDetailOpen(true); }}
          >
            <text flexShrink={1}>{on ? <strong fg={theme.accent}>{name}</strong> : <span fg={color}>{name}</span>}</text>
            <text flexShrink={0} fg={theme.dim}>{count}</text>
          </box>
        );
      })}
    </box>
  );

  const memberRows = Math.max(1, height - 16);
  const detail = selected ? (
    <box
      flexDirection="column"
      flexGrow={1}
      border
      borderStyle="rounded"
      borderColor={confirmDelete ? theme.danger : theme.border}
      paddingX={1}
      title={` ${truncate(selected.name, 40)} `}
      titleColor={selected.id ? theme.accent : theme.muted}
    >
      <FieldRow label="Secrets" value={String(selected.secretCount)} />
      {selected.createdAt ? <FieldRow label="Created" value={formatDate(selected.createdAt)} color={theme.dim} /> : <FieldRow label="About" value="Secrets not in any group" color={theme.dim} />}
      <box flexDirection="column" marginTop={1}>
        {members.length === 0 ? <text fg={theme.dim}>No secrets in this group.</text> : null}
        {members.slice(0, memberRows).map((entry) => {
          const badge = typeBadge(entry.type);
          return (
            <text key={entry.id}>
              <span fg={badge.color}>  {badge.glyph} </span>
              <span fg={theme.text}>{entry.name}</span>
            </text>
          );
        })}
        {members.length > memberRows ? <text fg={theme.dim}>  … {members.length - memberRows} more — enter to see all</text> : null}
      </box>
      {confirmDelete && selectedGroup ? (
        <box flexDirection="column" marginTop={1}>
          <text fg={theme.danger}><strong>Delete group "{selectedGroup.name}"?</strong></text>
          <text fg={theme.muted} wrapMode="word">{plural(selectedGroup.secretCount, "secret")} become ungrouped, none deleted.</text>
          <text fg={theme.muted}><Chip label="y" color={theme.danger} /> delete   <Chip label="n" /> cancel</text>
        </box>
      ) : null}
    </box>
  ) : (
    <box flexGrow={1} border borderStyle="rounded" borderColor={theme.border} padding={1}>
      <text fg={theme.dim}>Nothing selected.</text>
    </box>
  );

  return (
    <box flexDirection="column" flexGrow={1} width="100%">
      <box flexDirection="row" paddingX={1} height={1}>
        <text bg={searching ? theme.accent : theme.chip} fg={searching ? theme.onAccent : theme.muted}> / </text>
        <TextField value={query} onChange={(v) => { setQuery(v); setSelectedKey(null); }} focused={searching && app.active} placeholder="filter groups…" />
      </box>
      <box flexDirection="row" flexGrow={1} gap={1}>
        {wide || !detailOpen ? list : null}
        {showDetail ? detail : null}
      </box>
      {naming ? (
        <NamePrompt
          title={naming.mode === "create" ? " New group " : ` Rename ${truncate(naming.group.name, 40)} `}
          initial={naming.mode === "rename" ? naming.group.name : ""}
          setHints={setHints}
          onSave={saveName}
          onClose={() => setNaming(null)}
        />
      ) : null}
      {addingSecrets && selectedGroup ? (
        <GroupMembersPicker
          group={selectedGroup}
          entries={entries}
          onToggle={toggleMember}
          onClose={() => setAddingSecrets(false)}
        />
      ) : null}
    </box>
  );
}

/** One-field overlay for a group name; `onSave` returns an error to show, or null when done. */
function NamePrompt({ title, initial, setHints, onSave, onClose }: {
  title: string;
  initial: string;
  setHints: (hints: KeyHint[]) => void;
  onSave: (name: string) => string | null;
  onClose: () => void;
}) {
  const app = useApp();
  const { width } = useTerminalDimensions();
  const [name, setName] = useState(initial);
  const [error, setError] = useState("");
  // Enter can arrive before React re-renders with the latest keystrokes.
  const latest = useRef(initial);

  useKeyboard((key) => {
    if (!app.active || key.meta) return;
    if (key.name === "escape") { key.preventDefault(); onClose(); return; }
    if (isEnter(key)) { key.preventDefault(); setError(onSave(latest.current) ?? ""); }
  });

  useEffect(() => setHints([["enter", "save"], ["esc", "cancel"]]), [setHints]);

  const boxWidth = Math.min(60, Math.max(30, width - 4));
  return (
    <box position="absolute" top={2} left={Math.max(0, Math.floor((width - boxWidth) / 2))} width={boxWidth} zIndex={100}>
      <box flexDirection="column" border borderStyle="rounded" borderColor={theme.borderFocus} backgroundColor={theme.panel} paddingX={1} title={title} titleColor={theme.accent} titleAlignment="center">
        <box flexDirection="row" height={1} gap={1}>
          <text fg={theme.accent} width={6} flexShrink={0}>Name</text>
          <TextField value={name} onChange={(v) => { latest.current = v; setName(v); setError(""); }} focused={app.active} placeholder="e.g. homelab" />
        </box>
        {error ? <text fg={theme.danger}>✗ {error}</text> : null}
      </box>
    </box>
  );
}

/**
 * Overlay to pick an existing group, or "(none)" to ungroup. Groups are
 * created in the Groups tab, not here.
 */
export function GroupPicker({ groups, currentId, onPick, onClose }: {
  groups: GroupSummary[];
  /** The secret's group now; null when ungrouped. */
  currentId: string | null;
  /** Receives the picked group, or null for "(none)". */
  onPick: (group: GroupSummary | null) => void;
  onClose: () => void;
}) {
  const { width, height } = useTerminalDimensions();
  const [query, setQuery] = useState("");
  const [index, setIndex] = useState(0);
  const latestQuery = useRef("");

  type Option = { group: GroupSummary | null; label: string };
  const options = useMemo<Option[]>(() => [{ group: null, label: "(none)" }, ...groups.map((g) => ({ group: g, label: g.name }))], [groups]);
  const search = (q: string) => fuzzyFilter(options, q, (o) => [o.label]);
  const results = useMemo(() => search(query), [options, query]);
  const current = Math.min(index, Math.max(0, results.length - 1));

  useKeyboard((key) => {
    if (key.name === "escape") { key.preventDefault(); onClose(); return; }
    if (key.name === "up") { key.preventDefault(); setIndex(Math.max(0, current - 1)); return; }
    if (key.name === "down") { key.preventDefault(); setIndex(Math.min(results.length - 1, current + 1)); return; }
    if (key.name === "pageup") { key.preventDefault(); setIndex(Math.max(0, current - 10)); return; }
    if (key.name === "pagedown") { key.preventDefault(); setIndex(Math.min(results.length - 1, current + 10)); return; }
    if (isEnter(key)) {
      key.preventDefault();
      const fresh = latestQuery.current === query ? results : search(latestQuery.current);
      const option = fresh[latestQuery.current === query ? current : 0];
      if (option) onPick(option.group);
    }
  });

  const boxWidth = Math.min(60, Math.max(30, width - 4));
  const rows = Math.max(3, Math.min(14, height - 8));
  const offset = Math.max(0, Math.min(current - Math.floor(rows / 2), results.length - rows));
  const visible = results.slice(offset, offset + rows);
  const inner = boxWidth - 4;

  return (
    <box position="absolute" top={2} left={Math.max(0, Math.floor((width - boxWidth) / 2))} width={boxWidth} zIndex={100}>
      <box flexDirection="column" border borderStyle="rounded" borderColor={theme.borderFocus} backgroundColor={theme.panel} paddingX={1} title=" Group " titleColor={theme.accent} titleAlignment="center">
        <box flexDirection="row" height={1} gap={1}>
          <text fg={theme.accent}><strong>›</strong></text>
          <TextField value={query} onChange={(v) => { latestQuery.current = v; setQuery(v); setIndex(0); }} focused placeholder="search groups" />
        </box>
        <box flexDirection="column" marginTop={1}>
          {visible.length === 0 ? <text fg={theme.dim}>No matching groups — create them in the Groups tab</text> : null}
          {visible.map((option, i) => {
            const on = offset + i === current;
            const chosen = (option.group?.id ?? null) === currentId;
            const count = option.group ? String(option.group.secretCount) : "";
            const label = truncate(option.label, Math.max(4, inner - 4 - count.length));
            return (
              <box
                key={option.group?.id ?? "none"}
                flexDirection="row"
                justifyContent="space-between"
                height={1}
                backgroundColor={on ? theme.selection : undefined}
                onMouseDown={(event) => { event.preventDefault(); onPick(option.group); }}
                onMouseOver={() => setIndex(offset + i)}
              >
                <text>
                  <span fg={chosen ? theme.success : theme.dim}>{chosen ? " ✓ " : "   "}</span>
                  {on ? <strong fg={theme.accent}>{label}</strong> : <span fg={option.group ? theme.text : theme.muted}>{label}</span>}
                </text>
                {count ? <text flexShrink={0} fg={theme.dim}>{count}</text> : null}
              </box>
            );
          })}
        </box>
        <text marginTop={1}><Chip label="↑↓" /><span fg={theme.muted}> move  </span><Chip label="enter" /><span fg={theme.muted}> choose  </span><Chip label="esc" /><span fg={theme.muted}> cancel</span></text>
      </box>
    </box>
  );
}

/**
 * Overlay for adding secrets to `group`, the same as the link picker. Enter
 * puts the highlighted secret in the group or takes it out, and keeps the
 * picker open, so several can be toggled. A secret in another group moves.
 */
function GroupMembersPicker({ group, entries, onToggle, onClose }: {
  group: GroupSummary;
  entries: SecretIndexEntry[];
  onToggle: (entry: SecretIndexEntry) => void;
  onClose: () => void;
}) {
  const { width, height } = useTerminalDimensions();
  const [query, setQuery] = useState("");
  /** Highlighted row and first visible row; kept together so wheel ticks and key repeat compose. */
  const [view, setView] = useState({ index: 0, top: 0 });
  // Enter can arrive before React re-renders with the latest keystrokes.
  const latestQuery = useRef("");

  const search = (q: string) => fuzzyFilter(entries, q, (e) => [e.name, e.username, e.url, typeLabel(e.type)]);
  const results = useMemo(() => search(query), [entries, query]);
  const rows = Math.max(3, Math.min(14, height - 8));
  const maxTop = Math.max(0, results.length - rows);

  // The view only scrolls when the highlight would leave it, so the row under the pointer stays put.
  const place = (index: number, top: number) => {
    const i = Math.max(0, Math.min(results.length - 1, index));
    const t = Math.max(0, Math.min(maxTop, top, i), i - rows + 1);
    return { index: i, top: t };
  };
  const { index: current, top: offset } = place(view.index, view.top);
  const step = (delta: number) => setView((v) => place(v.index + delta, v.top));
  // The wheel scrolls the view and drags the highlight along when it falls off an edge.
  const scroll = (delta: number) => setView((v) => {
    const top = Math.max(0, Math.min(maxTop, v.top + delta));
    return place(Math.max(top, Math.min(top + rows - 1, v.index)), top);
  });

  useKeyboard((key) => {
    if (key.name === "escape") { key.preventDefault(); onClose(); return; }
    if (key.name === "up") { key.preventDefault(); step(-1); return; }
    if (key.name === "down") { key.preventDefault(); step(1); return; }
    if (key.name === "pageup") { key.preventDefault(); step(-10); return; }
    if (key.name === "pagedown") { key.preventDefault(); step(10); return; }
    if (isEnter(key)) {
      key.preventDefault();
      const fresh = latestQuery.current === query ? results : search(latestQuery.current);
      const entry = fresh[latestQuery.current === query ? current : 0];
      if (entry) onToggle(entry);
    }
  });

  const boxWidth = Math.min(72, Math.max(30, width - 4));
  const visible = results.slice(offset, offset + rows);
  const inner = boxWidth - 4;

  return (
    <box position="absolute" top={2} left={Math.max(0, Math.floor((width - boxWidth) / 2))} width={boxWidth} zIndex={100}>
      <box
        flexDirection="column"
        border
        borderStyle="rounded"
        borderColor={theme.borderFocus}
        backgroundColor={theme.panel}
        paddingX={1}
        title={` Add to ${truncate(group.name, 40)} `}
        titleColor={theme.accent}
        titleAlignment="center"
        onMouseScroll={(event) => {
          event.stopPropagation();
          scroll(event.scroll?.direction === "up" ? -3 : 3);
        }}
      >
        <box flexDirection="row" height={1} gap={1}>
          <text fg={theme.accent}><strong>›</strong></text>
          <TextField value={query} onChange={(v) => { latestQuery.current = v; setQuery(v); setView({ index: 0, top: 0 }); }} focused placeholder="search secrets to add" />
        </box>
        <box flexDirection="column" marginTop={1}>
          {visible.length === 0 ? <text fg={theme.dim}>No matching secrets</text> : null}
          {visible.map((entry, i) => {
            const on = offset + i === current;
            const member = entry.groupId === group.id;
            const elsewhere = !member && entry.group ? entry.group : null;
            const badge = typeBadge(entry.type);
            const name = truncate(entry.name, Math.max(4, inner - 6 - (elsewhere ? elsewhere.length + 4 : 0)));
            return (
              <box
                key={entry.id}
                flexDirection="row"
                height={1}
                backgroundColor={on ? theme.selection : undefined}
                onMouseDown={(event) => { event.preventDefault(); onToggle(entry); }}
                onMouseOver={() => setView((v) => place(offset + i, v.top))}
              >
                <text>
                  <span fg={member ? theme.success : theme.dim}>{member ? " ✓ " : "   "}</span>
                  <span fg={badge.color}>{badge.glyph} </span>
                  {on ? <strong fg={theme.accent}>{name}</strong> : <span fg={theme.text}>{name}</span>}
                  {elsewhere ? <span fg={theme.dim}>{`  · ${elsewhere}`}</span> : null}
                </text>
              </box>
            );
          })}
        </box>
        <text marginTop={1}><Chip label="↑↓" /><span fg={theme.muted}> move  </span><Chip label="enter" /><span fg={theme.muted}> add/remove  </span><Chip label="esc" /><span fg={theme.muted}> done</span></text>
      </box>
    </box>
  );
}
