import { useKeyboard, useTerminalDimensions } from "@opentui/react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { numberPreference } from "../../../../packages/core/src/index.ts";
import type { LeaseCoverage, LeaseState, SecretIndexEntry, VaultSession } from "../../../../packages/core/src/index.ts";
import { Chip, FieldRow, TextField, useNow, type KeyHint } from "./components.tsx";
import { handlePageKey, useApp, useScreenContext, type Command } from "./context.tsx";
import { theme, typeBadge, typeLabel } from "./theme.ts";
import { formatDate, formatDuration, fuzzyFilter, isEnter, parseDuration, relativeTime, truncate } from "./util.ts";

type Lease = LeaseState & { coverage: LeaseCoverage[] };
type LeaseStatus = "active" | "expired" | "revoked";

const STATUS_COLOR: Record<LeaseStatus, string> = { active: theme.success, expired: theme.dim, revoked: theme.danger };
const MAX_TTL_SECONDS = 2_592_000;
const WIDE_MIN_COLUMNS = 96;

const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

function statusOf(lease: LeaseState, now: number): LeaseStatus {
  if (lease.revokedAt) return "revoked";
  return Date.parse(lease.expiresAt) <= now ? "expired" : "active";
}

function whenLabel(lease: LeaseState, status: LeaseStatus, now: number): string {
  if (status === "revoked") return `revoked ${relativeTime(lease.revokedAt!, now)}`;
  return status === "active" ? `expires ${relativeTime(lease.expiresAt, now)}` : `expired ${relativeTime(lease.expiresAt, now)}`;
}

/** Leases: time-boxed grants over a set of secrets, like `autho lease`. */
export function LeasesScreen({ session, setHints }: { session: VaultSession; setHints: (hints: KeyHint[]) => void }) {
  const app = useApp();
  const { width, height } = useTerminalDimensions();
  const wide = width >= WIDE_MIN_COLUMNS;
  const now = useNow(15_000);
  const [leases, setLeases] = useState<Lease[]>([]);
  const [showAll, setShowAll] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detailOpen, setDetailOpen] = useState(false);
  const [confirmRevoke, setConfirmRevoke] = useState(false);
  const [creating, setCreating] = useState(false);

  const reload = useCallback(() => {
    try {
      setLeases(session.listLeases(200).map((lease) => ({ ...lease, coverage: session.showLease(lease.id).coverage })));
    } catch (e) {
      app.toast(message(e), "error");
    }
  }, [session, app]);

  useEffect(reload, [reload]);

  const visible = useMemo(() => leases.filter((lease) => showAll || statusOf(lease, now) === "active"), [leases, showAll, now]);
  const selectedIndex = Math.max(0, visible.findIndex((l) => l.id === selectedId));
  const selected = visible[selectedIndex] ?? null;
  const hiddenCount = leases.length - visible.length;
  const canRevoke = selected !== null && statusOf(selected, now) === "active";
  const showDetail = wide || detailOpen;

  const move = (delta: number) => {
    if (visible.length === 0) return;
    setSelectedId(visible[Math.max(0, Math.min(visible.length - 1, selectedIndex + delta))]!.id);
    setConfirmRevoke(false);
  };

  const revoke = () => {
    if (!selected) return;
    setConfirmRevoke(false);
    try {
      session.revokeLease(selected.id);
      app.toast(`Revoked "${selected.name}"`);
      reload();
    } catch (e) {
      app.toast(message(e), "error");
    }
  };

  const toggleAll = () => setShowAll((v) => !v);
  const listHeight = Math.max(3, height - 8);

  useKeyboard((key) => {
    if (!app.active || key.ctrl || key.meta || creating) return;
    if (confirmRevoke) {
      key.preventDefault();
      if (key.name === "y" || isEnter(key)) revoke();
      else if (key.name === "n" || key.name === "escape") setConfirmRevoke(false);
      return;
    }
    if (handlePageKey(app, key)) return;
    switch (key.name) {
      case "up": case "k": move(-1); return;
      case "down": case "j": move(1); return;
      case "pageup": move(-listHeight); return;
      case "pagedown": move(listHeight); return;
      case "g": move(key.shift ? visible.length : -visible.length); return;
      case "home": move(-visible.length); return;
      case "end": move(visible.length); return;
      case "n": setCreating(true); return;
      case "a": toggleAll(); return;
      case "r": reload(); app.toast("Reloaded", "info"); return;
      case "x": case "d": case "delete": if (canRevoke) setConfirmRevoke(true); return;
      case "q": app.go("vault"); return;
      case "?": app.openPalette(); return;
      case "escape":
        if (!wide && detailOpen) setDetailOpen(false);
        else app.go("vault");
        return;
    }
    if (isEnter(key) && !wide && selected) setDetailOpen(true);
  });

  const commands = useMemo<Command[]>(() => [
    { id: "lease:new", title: "New lease", hint: "n", group: "Leases", run: () => setCreating(true) },
    { id: "lease:reload", title: "Reload leases", hint: "r", group: "Leases", run: () => { reload(); app.toast("Reloaded", "info"); } },
    { id: "lease:all", title: showAll ? "Show active leases only" : "Show expired and revoked leases", hint: "a", group: "Leases", run: toggleAll },
    ...(canRevoke ? [{ id: "lease:revoke", title: `Revoke "${selected!.name}"`, hint: "x", group: "Selected", run: () => setConfirmRevoke(true) }] : []),
  ], [reload, app, showAll, canRevoke, selected]);
  useScreenContext(commands, selected ? { label: "Lease ID", read: () => selected.id, secret: false } : null);

  useEffect(() => {
    if (creating) return; // The new-lease panel shows its own keys.
    if (confirmRevoke) setHints([["y", "revoke"], ["n/esc", "cancel"]]);
    else setHints([["↑↓", "move"], ...(!wide && !detailOpen ? [["enter", "open"] as KeyHint] : []), ["n", "new"], ...(canRevoke ? [["x", "revoke"] as KeyHint] : []), ["a", showAll ? "active only" : "show ended"], ["r", "reload"], ["esc", "vault"]]);
  }, [creating, confirmRevoke, wide, detailOpen, canRevoke, showAll, setHints]);

  const listWidth = wide ? Math.max(40, Math.floor(width * 0.42)) : width;
  const offset = Math.max(0, Math.min(selectedIndex - Math.floor(listHeight / 2), visible.length - listHeight));
  const rows = visible.slice(offset, offset + listHeight);

  const list = (
    <box
      flexDirection="column"
      width={wide ? listWidth : "100%"}
      flexShrink={0}
      border
      borderStyle="rounded"
      borderColor={theme.border}
      title={` ${visible.length} lease${visible.length === 1 ? "" : "s"}${hiddenCount ? ` (+${hiddenCount} ended)` : ""} `}
      titleColor={theme.muted}
      onMouseScroll={(event) => move(event.scroll?.direction === "up" ? -3 : 3)}
    >
      {visible.length === 0 ? (
        <box padding={1} flexDirection="column" gap={1}>
          <text fg={theme.dim}>{showAll ? "No leases yet" : "No active leases"} — press n to create one.</text>
          <text fg={theme.dim} wrapMode="word">A lease grants time-boxed access to some secrets, for `autho exec --lease` and the daemon.</text>
        </box>
      ) : rows.map((lease) => {
        const on = lease.id === selected?.id;
        const status = statusOf(lease, now);
        const count = `${lease.coverage.length} secret${lease.coverage.length === 1 ? "" : "s"}`;
        const when = whenLabel(lease, status, now);
        // Inside the border and padding: "● " + name + "  " + when, then the count on the right.
        const name = truncate(lease.name, Math.max(6, listWidth - 4 - 2 - 2 - when.length - 1 - count.length));
        return (
          <box
            key={lease.id}
            flexDirection="row"
            height={1}
            paddingX={1}
            justifyContent="space-between"
            backgroundColor={on ? theme.selection : undefined}
            onMouseDown={() => { setSelectedId(lease.id); setConfirmRevoke(false); if (!wide) setDetailOpen(true); }}
          >
            <text flexShrink={1}>
              <span fg={STATUS_COLOR[status]}>● </span>
              {on ? <strong fg={theme.accent}>{name}</strong> : <span fg={theme.text}>{name}</span>}
              <span fg={theme.dim}>  {when}</span>
            </text>
            <text flexShrink={0} fg={theme.dim}>{count}</text>
          </box>
        );
      })}
    </box>
  );

  const detail = selected ? (
    <box
      flexDirection="column"
      flexGrow={1}
      border
      borderStyle="rounded"
      borderColor={confirmRevoke ? theme.danger : theme.border}
      paddingX={1}
      title={` ${truncate(selected.name, 40)} `}
      titleColor={STATUS_COLOR[statusOf(selected, now)]}
    >
      <FieldRow label="Status" value={statusOf(selected, now)} color={STATUS_COLOR[statusOf(selected, now)]} />
      <FieldRow label="ID" value={selected.id} color={theme.muted} />
      <FieldRow label="Created" value={formatDate(selected.createdAt)} />
      {selected.revokedAt
        ? <FieldRow label="Revoked" value={`${formatDate(selected.revokedAt)} · ${relativeTime(selected.revokedAt, now)}`} color={theme.danger} />
        : <FieldRow label={statusOf(selected, now) === "active" ? "Expires" : "Expired"} value={`${formatDate(selected.expiresAt)} · ${relativeTime(selected.expiresAt, now)}`} />}
      <FieldRow label="Links" value={selected.includeLinks ? "included" : "not included"} color={selected.includeLinks ? theme.text : theme.muted} />
      <text marginTop={1} fg={theme.muted}>Covers {selected.coverage.length} secret{selected.coverage.length === 1 ? "" : "s"}</text>
      {selected.coverage.slice(0, Math.max(1, height - 18)).map((secret) => {
        const badge = typeBadge(secret.type);
        return (
          <text key={secret.id}>
            <span fg={badge.color}>  {badge.glyph} </span>
            <span fg={theme.text}>{secret.name}</span>
            {secret.via ? <span fg={theme.dim}>  via {secret.via.name}</span> : null}
          </text>
        );
      })}
      {confirmRevoke ? (
        <box flexDirection="column" marginTop={1}>
          <text fg={theme.danger}><strong>Revoke "{selected.name}"?</strong></text>
          <text fg={theme.muted} wrapMode="word">Anything using this lease loses access right away.</text>
          <text fg={theme.muted}><Chip label="y" color={theme.danger} /> revoke   <Chip label="n" /> cancel</text>
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
      <box flexDirection="row" flexGrow={1} gap={1}>
        {wide || !detailOpen ? list : null}
        {showDetail ? detail : null}
      </box>
      {creating ? (
        <NewLease
          session={session}
          setHints={setHints}
          onClose={() => setCreating(false)}
          onCreated={(lease) => {
            setCreating(false);
            setShowAll(false);
            setSelectedId(lease.id);
            app.toast(`Created lease "${lease.name}" · ${relativeTime(lease.expiresAt)}`);
            reload();
          }}
        />
      ) : null}
    </box>
  );
}

type Field = "name" | "ttl" | "secrets" | "links";
const FIELDS: Field[] = ["name", "ttl", "secrets", "links"];

/** Overlay to create a lease: name, TTL, a multi-select of secrets, and whether linked secrets ride along. */
function NewLease({ session, setHints, onClose, onCreated }: {
  session: VaultSession;
  setHints: (hints: KeyHint[]) => void;
  onClose: () => void;
  onCreated: (lease: LeaseState) => void;
}) {
  const app = useApp();
  const { width, height } = useTerminalDimensions();
  const entries = useMemo<SecretIndexEntry[]>(() => {
    try {
      return session.listSecretIndex();
    } catch {
      return [];
    }
  }, [session]);
  const [field, setField] = useState<Field>("name");
  const [name, setName] = useState("");
  const [ttl, setTtl] = useState(() => {
    const fallback = numberPreference("defaultLeaseTtl");
    return fallback > 0 ? formatDuration(fallback) : "1h";
  });
  const [query, setQuery] = useState("");
  const [cursor, setCursor] = useState(0);
  const [picked, setPicked] = useState<Set<string>>(() => new Set());
  const [includeLinks, setIncludeLinks] = useState(true);
  const [error, setError] = useState("");
  // Keys can arrive before React re-renders with the latest typing.
  const latest = useRef({ name, ttl, query });

  const candidates = useMemo(() => fuzzyFilter(entries, query, (e) => [e.name, e.username, e.url, typeLabel(e.type)]), [entries, query]);
  const current = Math.min(cursor, Math.max(0, candidates.length - 1));

  const toggle = (entry: SecretIndexEntry) => {
    setError("");
    setPicked((prev) => {
      const next = new Set(prev);
      if (next.has(entry.id)) next.delete(entry.id);
      else next.add(entry.id);
      return next;
    });
  };

  const create = () => {
    const seconds = parseDuration(latest.current.ttl);
    if (seconds === null || seconds <= 0) { setError("Expires after: use a duration like 90s, 15m, 2h or 1d"); setField("ttl"); return; }
    if (seconds > MAX_TTL_SECONDS) { setError("Expires after: at most 30 days"); setField("ttl"); return; }
    if (picked.size === 0) { setError("Pick at least one secret"); setField("secrets"); return; }
    try {
      onCreated(session.createLease({ name: latest.current.name.trim() || "tui", noLinks: !includeLinks, secretRefs: [...picked], ttlSeconds: seconds }));
    } catch (e) {
      setError(message(e));
    }
  };

  const cycle = (delta: number) => setField((f) => FIELDS[(FIELDS.indexOf(f) + delta + FIELDS.length) % FIELDS.length]!);

  useKeyboard((key) => {
    if (!app.active || key.meta) return;
    if (key.name === "escape") { key.preventDefault(); onClose(); return; }
    if (key.ctrl && key.name === "s") { key.preventDefault(); create(); return; }
    if (key.ctrl) return;
    if (key.name === "tab") { key.preventDefault(); cycle(key.shift ? -1 : 1); return; }
    if (field === "secrets") {
      if (key.name === "up") { key.preventDefault(); setCursor(Math.max(0, current - 1)); return; }
      if (key.name === "down") { key.preventDefault(); setCursor(Math.min(candidates.length - 1, current + 1)); return; }
      if (isEnter(key)) {
        key.preventDefault();
        const fresh = latest.current.query === query ? candidates : fuzzyFilter(entries, latest.current.query, (e) => [e.name, e.username, e.url, typeLabel(e.type)]);
        const entry = fresh[latest.current.query === query ? current : 0];
        if (entry) toggle(entry);
      }
      return;
    }
    if (field === "links") {
      if (key.name === "space" || isEnter(key) || key.name === "left" || key.name === "right") { key.preventDefault(); setIncludeLinks((v) => !v); return; }
      if (key.name === "up") { key.preventDefault(); cycle(-1); }
      return;
    }
    if (isEnter(key) || key.name === "down") { key.preventDefault(); cycle(1); return; }
    if (key.name === "up") { key.preventDefault(); cycle(-1); }
  });

  useEffect(() => {
    const keys: KeyHint[] = field === "secrets" ? [["↑↓", "move"], ["enter", "pick"]] : field === "links" ? [["space", "toggle"]] : [["enter", "next"]];
    setHints([...keys, ["tab", "field"], ["ctrl+s", "create"], ["esc", "cancel"]]);
  }, [field, setHints]);

  const boxWidth = Math.min(76, Math.max(40, width - 4));
  const listRows = Math.max(3, Math.min(10, height - 16));
  const offset = Math.max(0, Math.min(current - Math.floor(listRows / 2), candidates.length - listRows));
  const shown = candidates.slice(offset, offset + listRows);
  const inner = boxWidth - 4;
  const label = (f: Field, text: string) => <text width={10} flexShrink={0} fg={field === f ? theme.accent : theme.muted}>{field === f ? "› " : "  "}{text}</text>;
  const active = app.active;

  return (
    <box position="absolute" top={2} left={Math.max(0, Math.floor((width - boxWidth) / 2))} width={boxWidth} zIndex={100}>
      <box flexDirection="column" border borderStyle="rounded" borderColor={theme.borderFocus} backgroundColor={theme.panel} paddingX={1} title=" New lease " titleColor={theme.accent} titleAlignment="center">
        <box flexDirection="row" height={1} gap={1} onMouseDown={() => setField("name")}>
          {label("name", "Name")}
          <TextField value={name} onChange={(v) => { latest.current.name = v; setName(v); }} focused={active && field === "name"} placeholder="tui" />
        </box>
        <box flexDirection="row" height={1} gap={1} onMouseDown={() => setField("ttl")}>
          {label("ttl", "Expires")}
          <TextField value={ttl} onChange={(v) => { latest.current.ttl = v; setTtl(v); setError(""); }} focused={active && field === "ttl"} placeholder="1h" />
          <text flexShrink={0} fg={theme.dim}>90s · 15m · 2h · 1d</text>
        </box>
        <box flexDirection="row" height={1} gap={1} marginTop={1} onMouseDown={() => setField("secrets")}>
          {label("secrets", "Secrets")}
          <TextField value={query} onChange={(v) => { latest.current.query = v; setQuery(v); setCursor(0); }} focused={active && field === "secrets"} placeholder="search, enter to pick" />
          <text flexShrink={0} fg={picked.size ? theme.accent : theme.dim}>{picked.size} picked</text>
        </box>
        <box flexDirection="column" height={listRows}>
          {shown.length === 0 ? <text fg={theme.dim}>  No secrets{query ? " match" : ""}</text> : null}
          {shown.map((entry, i) => {
            const on = field === "secrets" && offset + i === current;
            const isPicked = picked.has(entry.id);
            const badge = typeBadge(entry.type);
            const extra = entry.linkCount ? `+${entry.linkCount} linked` : "";
            const entryName = truncate(entry.name, Math.max(4, inner - 8 - extra.length));
            return (
              <box
                key={entry.id}
                flexDirection="row"
                height={1}
                justifyContent="space-between"
                backgroundColor={on ? theme.selection : undefined}
                onMouseDown={(event) => { event.preventDefault(); setField("secrets"); setCursor(offset + i); toggle(entry); }}
              >
                <text>
                  <span fg={isPicked ? theme.success : theme.dim}>{isPicked ? " ✓ " : " · "}</span>
                  <span fg={badge.color}>{badge.glyph} </span>
                  {on ? <strong fg={theme.accent}>{entryName}</strong> : <span fg={theme.text}>{entryName}</span>}
                </text>
                {extra ? <text flexShrink={0} fg={theme.dim}>{extra}</text> : null}
              </box>
            );
          })}
        </box>
        <box flexDirection="row" height={1} gap={1} marginTop={1} onMouseDown={() => { setField("links"); setIncludeLinks((v) => !v); }}>
          {label("links", "Links")}
          <text><span fg={includeLinks ? theme.success : theme.dim}>{includeLinks ? "[✓]" : "[ ]"}</span><span fg={theme.text}> include linked secrets</span></text>
        </box>
        {error ? <text fg={theme.danger}>✗ {error}</text> : null}
      </box>
    </box>
  );
}
