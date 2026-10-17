import { RefreshCw, ScrollText, Search } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { toast } from "sonner";

import { Button } from "../components/ui/button.tsx";
import { Empty, Panel, Spinner } from "../components/ui/panel.tsx";
import { useApp, useScreen, type Command, type KeyHint } from "../context.tsx";
import { AUDIT_SOURCES, api, errorMessage, type AuditEvent } from "../lib/api.ts";
import { cn, formatDate, fuzzyFilter, isTypingTarget, relativeTime } from "../lib/utils.ts";

const LIMITS = [100, 200, 500] as const;

/** Colour by what kind of thing happened: reads, writes, removals, security. */
function toneOf(eventType: string): string {
  if (/delete|remove|revoke|tamper|quarantine|fail/i.test(eventType)) return "text-danger";
  if (/reveal|copy|read|otp|export|lease\.use|exec/i.test(eventType)) return "text-info";
  if (/password|totp|passkey|recovery|pin|keychain|reseal|admin|unlock|lock/i.test(eventType)) return "text-accent";
  if (/create|add|link|import|update/i.test(eventType)) return "text-success";
  return "text-muted";
}

/** The lease an event went through, by the name it had at the time. */
function leaseLabel(event: AuditEvent): string | null {
  if (!event.leaseId) return null;
  return typeof event.metadata?.leaseName === "string" ? `${event.metadata.leaseName} · ${event.leaseId}` : event.leaseId;
}

function metadataValue(value: unknown): string {
  if (typeof value === "string") return value;
  // Injection events list the secrets they used as { envName, id, name }.
  if (Array.isArray(value) && value.every((v) => v && typeof v === "object" && "name" in v)) {
    return value.map((v) => String((v as { name: unknown }).name)).join(", ");
  }
  return JSON.stringify(value);
}

/** The vault's audit log, newest first, like `autho audit`. */
export function AuditScreen() {
  const app = useApp();
  const [events, setEvents] = useState<AuditEvent[] | null>(null);
  const [limit, setLimit] = useState<(typeof LIMITS)[number]>(200);
  const [source, setSource] = useState("");
  const [query, setQuery] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  const load = useCallback(async (quiet = true) => {
    try {
      setEvents(await api.audit(limit, source || undefined));
      if (!quiet) toast.success("Reloaded");
    } catch (error) {
      toast.error(errorMessage(error));
    }
  }, [limit, source]);

  useEffect(() => {
    void load();
  }, [load]);

  const visible = useMemo(
    () => (query ? fuzzyFilter(events ?? [], query, (e) => [e.eventType, e.message, e.subjectRef, e.subjectType, e.source, leaseLabel(e)]) : events ?? []),
    [events, query],
  );
  const selected = visible.find((e) => e.id === selectedId) ?? null;

  const move = useCallback((delta: number | "top" | "bottom") => {
    if (visible.length === 0) return;
    const index = selected ? visible.indexOf(selected) : -1;
    const next = delta === "top" ? 0 : delta === "bottom" ? visible.length - 1 : Math.max(0, Math.min(visible.length - 1, index + delta));
    setSelectedId(visible[next]!.id);
    listRef.current?.querySelector(`[data-id="${CSS.escape(visible[next]!.id)}"]`)?.scrollIntoView({ block: "nearest" });
  }, [visible, selected]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.defaultPrevented || app.paletteOpen || app.modalOpen || event.ctrlKey || event.metaKey || event.altKey || isTypingTarget(event.target)) return;
      const actions: Record<string, () => void> = {
        j: () => move(1),
        ArrowDown: () => move(1),
        k: () => move(-1),
        ArrowUp: () => move(-1),
        g: () => move("top"),
        G: () => move("bottom"),
        "/": () => searchRef.current?.focus(),
        r: () => void load(false),
        Escape: () => (selectedId ? setSelectedId(null) : query ? setQuery("") : app.go("vault")),
      };
      const action = actions[event.key];
      if (action) {
        event.preventDefault();
        action();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [app, move, load, selectedId, query]);

  const commands = useMemo<Command[]>(() => [
    { id: "audit:reload", title: "Reload audit log", group: "Audit", hint: "r", run: () => void load(false) },
    { id: "audit:search", title: "Search audit log", group: "Audit", hint: "/", run: () => searchRef.current?.focus() },
    ...LIMITS.map((n) => ({ id: `audit:limit:${n}`, title: `Show the last ${n} events`, group: "Audit", run: () => setLimit(n) })),
  ], [load]);
  const hints = useMemo<KeyHint[]>(() => [["j/k", "move"], ["/", "search"], ["r", "reload"], ["esc", "back"]], []);
  useScreen(commands, hints);

  return (
    <Panel
      className="h-full"
      title={<>Audit log <span className="text-dim">· {query ? `${visible.length} of ${events?.length ?? 0}` : events?.length ?? 0}</span></>}
      actions={
        <>
          <select
            value={source}
            onChange={(e) => setSource(e.target.value)}
            aria-label="Where events came from"
            className="h-7 cursor-pointer rounded-md border border-border bg-panel-alt px-2 text-xs text-text focus:border-border-focus focus:outline-none"
          >
            <option value="">all sources</option>
            {AUDIT_SOURCES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <select
            value={limit}
            onChange={(e) => setLimit(Number(e.target.value) as (typeof LIMITS)[number])}
            aria-label="How many events"
            className="h-7 cursor-pointer rounded-md border border-border bg-panel-alt px-2 text-xs text-text focus:border-border-focus focus:outline-none"
          >
            {LIMITS.map((n) => <option key={n} value={n}>last {n}</option>)}
          </select>
          <Button size="icon-sm" variant="ghost" onClick={() => void load(false)} aria-label="Reload" title="Reload (r)"><RefreshCw /></Button>
        </>
      }
      bodyClassName="flex flex-col"
    >
      <div className="flex items-center gap-2 border-b border-border px-4">
        <Search className="size-4 text-dim" />
        <input
          ref={searchRef}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Escape") {
              e.preventDefault();
              if (query) setQuery("");
              else e.currentTarget.blur();
            } else if (e.key === "Enter" || e.key === "ArrowDown") {
              e.preventDefault();
              e.currentTarget.blur();
              move("top");
            }
          }}
          placeholder="Filter by event, message, subject, source or lease"
          aria-label="Filter audit events"
          className="h-10 flex-1 bg-transparent text-sm text-text placeholder:text-dim focus:outline-none"
        />
      </div>
      <div ref={listRef} role="listbox" aria-label="Audit events" className="min-h-0 flex-1 overflow-y-auto p-1.5 font-mono text-xs">
        {events === null ? (
          <div className="flex justify-center py-10"><Spinner /></div>
        ) : visible.length === 0 ? (
          <Empty icon={<ScrollText />} title={query ? "No events match" : "No events yet"} />
        ) : (
          visible.map((event) => {
            const active = event.id === selectedId;
            const meta = Object.entries(event.metadata ?? {});
            return (
              <div
                key={event.id}
                role="option"
                aria-selected={active}
                data-id={event.id}
                onClick={() => setSelectedId(active ? null : event.id)}
                className={cn("cursor-pointer rounded-md border-l-2 px-2.5 py-1.5", active ? "border-accent bg-selection" : "border-transparent hover:bg-selection/50")}
              >
                <div className="flex items-baseline gap-3">
                  <time dateTime={event.createdAt} title={formatDate(event.createdAt)} className="w-24 shrink-0 text-dim">{relativeTime(event.createdAt)}</time>
                  <span className={cn("w-44 shrink-0 truncate", toneOf(event.eventType))}>{event.eventType}</span>
                  <span className={cn("min-w-0 flex-1 font-sans text-sm", active ? "text-text" : "truncate text-text/90")}>{event.message}</span>
                  {event.source ? <span className="shrink-0 rounded bg-panel-alt px-1.5 text-dim">{event.source}</span> : null}
                </div>
                {active ? (
                  <dl className="mt-2 grid grid-cols-[8rem_1fr] gap-x-3 gap-y-1 pb-1 pl-[6.75rem] text-muted">
                    <dt className="text-dim">time</dt><dd>{formatDate(event.createdAt)}</dd>
                    <dt className="text-dim">subject</dt><dd className="break-all">{event.subjectType}{event.subjectRef ? ` · ${event.subjectRef}` : ""}</dd>
                    <dt className="text-dim">source</dt><dd>{event.source ?? "unknown"}</dd>
                    {event.leaseId ? <><dt className="text-dim">lease</dt><dd className="break-all">{leaseLabel(event)}</dd></> : null}
                    {meta.map(([key, value]) => (
                      <div key={key} className="contents">
                        <dt className="truncate text-dim">{key}</dt>
                        <dd className="break-all">{metadataValue(value)}</dd>
                      </div>
                    ))}
                  </dl>
                ) : null}
              </div>
            );
          })
        )}
      </div>
    </Panel>
  );
}
