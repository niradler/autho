import { useKeyboard, useTerminalDimensions } from "@opentui/react";
import { useCallback, useEffect, useMemo, useState } from "react";

import type { AuditEvent, VaultSession } from "../../../../packages/core/src/index.ts";
import { FieldRow, TextField, useNow, type KeyHint } from "./components.tsx";
import { handlePageKey, useApp, useScreenContext, type Command } from "./context.tsx";
import { theme } from "./theme.ts";
import { formatDate, isEnter, relativeTime, truncate } from "./util.ts";

const LIMITS = [100, 200, 500] as const;
const WIDE_MIN_COLUMNS = 96;

const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

/** Colour for an event type, matching the web UI: destructive red, reads blue, auth gold, writes green. */
export function toneOf(eventType: string): string {
  if (/delete|remove|revoke|tamper|quarantine|fail/.test(eventType)) return theme.danger;
  if (/reveal|copy|read|otp|export|lease\.use|exec/.test(eventType)) return theme.info;
  if (/password|totp|passkey|recovery|pin|keychain|reseal|admin|unlock|lock/.test(eventType)) return theme.accent;
  if (/create|add|link|import|update/.test(eventType)) return theme.success;
  return theme.muted;
}

function subjectName(event: AuditEvent, names: Map<string, string>): string | null {
  return event.subjectRef ? (names.get(event.subjectRef) ?? null) : null;
}

function matches(event: AuditEvent, query: string, names: Map<string, string>): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  const fields = [event.eventType, event.message, event.subjectRef ?? "", event.subjectType, subjectName(event, names) ?? "", event.source ?? "", leaseLabel(event, names) ?? ""];
  return fields.some((field) => field.toLowerCase().includes(q));
}

/** The lease an event was made through, by name when it still exists. */
function leaseLabel(event: AuditEvent, names: Map<string, string>): string | null {
  if (!event.leaseId) return null;
  return names.get(event.leaseId) ?? (typeof event.metadata.leaseName === "string" ? event.metadata.leaseName : event.leaseId);
}

function metadataValue(value: unknown): string {
  if (typeof value === "string") return value;
  // Injection events list the secrets they used as { envName, id, name }.
  if (Array.isArray(value) && value.every((v) => v && typeof v === "object" && "name" in v)) {
    return value.map((v) => String((v as { name: unknown }).name)).join(", ");
  }
  return JSON.stringify(value);
}

/** Audit: the vault's event log, newest first, like `autho audit`. */
export function AuditScreen({ session, setHints }: { session: VaultSession; setHints: (hints: KeyHint[]) => void }) {
  const app = useApp();
  const { width, height } = useTerminalDimensions();
  const wide = width >= WIDE_MIN_COLUMNS;
  const now = useNow(30_000);
  const [limit, setLimit] = useState<(typeof LIMITS)[number]>(LIMITS[0]);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  // Events point at secrets and leases by id; show their names where they still exist.
  const [names, setNames] = useState<Map<string, string>>(() => new Map());
  const [query, setQuery] = useState("");
  const [filtering, setFiltering] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detailOpen, setDetailOpen] = useState(false);

  const reload = useCallback(() => {
    try {
      setEvents(session.listAudit({ limit }));
      setNames(new Map([
        ...session.listSecretIndex().map((e): [string, string] => [e.id, e.name]),
        ...session.listLeases(500).map((l): [string, string] => [l.id, l.name]),
      ]));
    } catch (e) {
      app.toast(message(e), "error");
    }
  }, [session, limit, app]);

  useEffect(reload, [reload]);

  const filtered = useMemo(() => events.filter((event) => matches(event, query, names)), [events, query, names]);
  const selectedIndex = Math.max(0, filtered.findIndex((e) => e.id === selectedId));
  const selected = filtered[selectedIndex] ?? null;
  const showDetail = wide || detailOpen;
  const listHeight = Math.max(3, height - 9);

  const move = (delta: number) => {
    if (filtered.length === 0) return;
    setSelectedId(filtered[Math.max(0, Math.min(filtered.length - 1, selectedIndex + delta))]!.id);
  };
  const cycleLimit = () => setLimit((l) => LIMITS[(LIMITS.indexOf(l) + 1) % LIMITS.length]!);
  const refresh = () => { reload(); app.toast("Reloaded", "info"); };

  useKeyboard((key) => {
    if (!app.active || key.ctrl || key.meta) return;
    if (filtering) {
      if (key.name === "escape") { setQuery(""); setFiltering(false); }
      else if (isEnter(key) || key.name === "down") { key.preventDefault(); setFiltering(false); }
      return;
    }
    if (handlePageKey(app, key)) return;
    switch (key.name) {
      case "up": case "k": move(-1); return;
      case "down": case "j": move(1); return;
      case "pageup": move(-listHeight); return;
      case "pagedown": move(listHeight); return;
      case "g": move(key.shift ? filtered.length : -filtered.length); return;
      case "home": move(-filtered.length); return;
      case "end": move(filtered.length); return;
      case "slash": key.preventDefault(); setFiltering(true); return;
      case "m": cycleLimit(); return;
      case "r": refresh(); return;
      case "q": app.go("vault"); return;
      case "escape":
        if (!wide && detailOpen) setDetailOpen(false);
        else if (query) setQuery("");
        else app.go("vault");
        return;
    }
    if (key.sequence === "/") { key.preventDefault(); setFiltering(true); return; }
    if (key.sequence === "?") { app.openPalette(); return; }
    if (isEnter(key) && !wide && selected) setDetailOpen(true);
  });

  const commands = useMemo<Command[]>(() => [
    { id: "audit:reload", title: "Reload audit log", hint: "r", group: "Audit", run: refresh },
    { id: "audit:filter", title: "Filter audit events", hint: "/", group: "Audit", run: () => setFiltering(true) },
    ...LIMITS.filter((l) => l !== limit).map((l) => ({ id: `audit:limit:${l}`, title: `Show the last ${l} events`, group: "Audit", run: () => setLimit(l) })),
  ], [limit, reload]);
  useScreenContext(commands, selected ? { label: "Event", read: () => `${selected.createdAt} ${selected.eventType} ${selected.message}`, secret: false } : null);

  useEffect(() => {
    if (filtering) setHints([["type", "filter"], ["enter/↓", "results"], ["esc", "clear"]]);
    else setHints([["↑↓", "move"], ...(!wide && !detailOpen ? [["enter", "open"] as KeyHint] : []), ["/", "filter"], ["m", `last ${LIMITS[(LIMITS.indexOf(limit) + 1) % LIMITS.length]}`], ["r", "reload"], ["esc", "vault"]]);
  }, [filtering, wide, detailOpen, limit, setHints]);

  const listWidth = wide ? Math.max(40, Math.floor(width * 0.5)) : width;
  const offset = Math.max(0, Math.min(selectedIndex - Math.floor(listHeight / 2), filtered.length - listHeight));
  const rows = filtered.slice(offset, offset + listHeight);
  const typeWidth = Math.min(24, Math.max(12, ...rows.map((e) => e.eventType.length)));

  const list = (
    <box
      flexDirection="column"
      width={wide ? listWidth : "100%"}
      flexShrink={0}
      border
      borderStyle="rounded"
      borderColor={theme.border}
      title={` ${query ? `${filtered.length}/` : ""}${events.length} events · last ${limit} `}
      titleColor={theme.muted}
      onMouseScroll={(event) => move(event.scroll?.direction === "up" ? -3 : 3)}
    >
      {filtered.length === 0 ? (
        <box padding={1}><text fg={theme.dim}>{query ? `No events match "${query}"` : "No events yet."}</text></box>
      ) : rows.map((event) => {
        const on = event.id === selected?.id;
        const when = relativeTime(event.createdAt, now);
        const type = truncate(event.eventType, typeWidth).padEnd(typeWidth);
        const source = event.source ?? "";
        const subject = truncate(subjectName(event, names) ?? event.message, Math.max(4, listWidth - typeWidth - when.length - source.length - 12));
        return (
          <box
            key={event.id}
            flexDirection="row"
            height={1}
            paddingX={1}
            justifyContent="space-between"
            backgroundColor={on ? theme.selection : undefined}
            onMouseDown={() => { setSelectedId(event.id); if (!wide) setDetailOpen(true); }}
          >
            <text flexShrink={1}>
              <span fg={toneOf(event.eventType)}>● </span>
              {on ? <strong fg={theme.accent}>{type}</strong> : <span fg={theme.text}>{type}</span>}
              <span fg={theme.muted}>  {subject}</span>
            </text>
            <text flexShrink={0} fg={theme.dim}>{source ? `${source} · ` : ""}{when}</text>
          </box>
        );
      })}
    </box>
  );

  const metadata = selected ? Object.entries(selected.metadata) : [];
  const detail = selected ? (
    <box flexDirection="column" flexGrow={1} border borderStyle="rounded" borderColor={theme.border} paddingX={1} title={` ${truncate(selected.eventType, 40)} `} titleColor={toneOf(selected.eventType)}>
      <text fg={theme.text} wrapMode="word" marginBottom={1}>{selected.message}</text>
      <FieldRow label="Time" value={`${formatDate(selected.createdAt)} · ${relativeTime(selected.createdAt, now)}`} />
      <FieldRow label="Subject" value={[selected.subjectType, subjectName(selected, names), selected.subjectRef].filter(Boolean).join(" · ")} />
      <FieldRow label="Source" value={selected.source ?? "unknown"} />
      {selected.leaseId ? <FieldRow label="Lease" value={[leaseLabel(selected, names), selected.leaseId].filter(Boolean).join(" · ")} /> : null}
      <FieldRow label="ID" value={selected.id} color={theme.muted} />
      {metadata.length ? <text marginTop={1} fg={theme.muted}>Details</text> : null}
      {metadata.slice(0, Math.max(1, height - 16)).map(([k, v]) => (
        <FieldRow key={k} label={`  ${truncate(k, 9)}`} value={truncate(metadataValue(v), 400)} color={theme.text} />
      ))}
    </box>
  ) : (
    <box flexGrow={1} border borderStyle="rounded" borderColor={theme.border} padding={1}>
      <text fg={theme.dim}>Nothing selected.</text>
    </box>
  );

  return (
    <box flexDirection="column" flexGrow={1} width="100%">
      <box flexDirection="row" paddingX={1} height={1}>
        <text bg={filtering ? theme.accent : theme.chip} fg={filtering ? theme.onAccent : theme.muted}> / </text>
        <TextField value={query} onChange={setQuery} focused={filtering && app.active} placeholder="filter by event, subject, source, lease…" />
      </box>
      <box flexDirection="row" flexGrow={1} gap={1}>
        {wide || !detailOpen ? list : null}
        {showDetail ? detail : null}
      </box>
    </box>
  );
}
