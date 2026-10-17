import { Check, KeyRound, Plus, RefreshCw } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from "react";
import { toast } from "sonner";

import { ConfirmDialog } from "../components/confirm-dialog.tsx";
import { Button } from "../components/ui/button.tsx";
import { Dialog, DialogContent, DialogFooter } from "../components/ui/dialog.tsx";
import { Field, Input } from "../components/ui/field.tsx";
import { Empty, Kbd, Panel, Spinner } from "../components/ui/panel.tsx";
import { Switch } from "../components/ui/switch.tsx";
import { useApp, useScreen, type Command, type KeyHint } from "../context.tsx";
import { api, errorMessage, type Lease, type SecretEntry } from "../lib/api.ts";
import { TYPE_META, cn, formatDate, formatDuration, fuzzyFilter, isTypingTarget, parseDuration, relativeTime } from "../lib/utils.ts";

type LeaseStatus = "active" | "expired" | "revoked";

function statusOf(lease: Lease, now: number): LeaseStatus {
  if (lease.revokedAt) return "revoked";
  return Date.parse(lease.expiresAt) <= now ? "expired" : "active";
}

const STATUS_STYLE: Record<LeaseStatus, string> = {
  active: "text-success",
  expired: "text-dim",
  revoked: "text-danger",
};

/** Leases: time-boxed grants over a set of secrets, like `autho lease`. */
export function LeasesScreen() {
  const app = useApp();
  const [leases, setLeases] = useState<Lease[] | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [showAll, setShowAll] = useState(false);
  const [dialog, setDialog] = useState<"new" | "revoke" | null>(null);
  const [now, setNow] = useState(Date.now());
  const listRef = useRef<HTMLDivElement>(null);
  const { setModalOpen } = app;

  const load = useCallback(async (quiet = true) => {
    try {
      setLeases(await api.leases());
      setNow(Date.now());
      if (!quiet) toast.success("Reloaded");
    } catch (error) {
      toast.error(errorMessage(error));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  // Keep the "expires in" labels and active/expired split current.
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 15_000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    setModalOpen(dialog !== null);
    return () => setModalOpen(false);
  }, [dialog, setModalOpen]);

  const visible = useMemo(
    () => (leases ?? []).filter((lease) => showAll || statusOf(lease, now) === "active"),
    [leases, showAll, now],
  );
  const selected = visible.find((l) => l.id === selectedId) ?? visible[0] ?? null;
  const hiddenCount = (leases?.length ?? 0) - visible.length;

  const move = useCallback((delta: number | "top" | "bottom") => {
    if (visible.length === 0) return;
    const index = selected ? visible.indexOf(selected) : 0;
    const next = delta === "top" ? 0 : delta === "bottom" ? visible.length - 1 : Math.max(0, Math.min(visible.length - 1, index + delta));
    setSelectedId(visible[next]!.id);
    listRef.current?.querySelector(`[data-id="${CSS.escape(visible[next]!.id)}"]`)?.scrollIntoView({ block: "nearest" });
  }, [visible, selected]);

  const canRevoke = selected !== null && statusOf(selected, now) === "active";

  const revoke = useCallback(async () => {
    if (!selected) return;
    try {
      await api.revokeLease(selected.id);
      toast.success(`Revoked "${selected.name}"`);
      await load();
    } catch (error) {
      toast.error(errorMessage(error));
    }
  }, [selected, load]);

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
        n: () => setDialog("new"),
        r: () => void load(false),
        a: () => setShowAll((v) => !v),
        x: () => canRevoke && setDialog("revoke"),
        d: () => canRevoke && setDialog("revoke"),
        Delete: () => canRevoke && setDialog("revoke"),
        Escape: () => app.go("vault"),
      };
      const action = actions[event.key];
      if (action) {
        event.preventDefault();
        action();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [app, move, load, canRevoke]);

  const commands = useMemo<Command[]>(() => [
    { id: "lease:new", title: "New lease", group: "Leases", hint: "n", run: () => setDialog("new") },
    { id: "lease:reload", title: "Reload leases", group: "Leases", hint: "r", run: () => void load(false) },
    { id: "lease:all", title: showAll ? "Show active leases only" : "Show expired and revoked leases", group: "Leases", hint: "a", run: () => setShowAll((v) => !v) },
    ...(canRevoke ? [{ id: "lease:revoke", title: `Revoke "${selected!.name}"`, group: "Selected", hint: "x", run: () => setDialog("revoke") }] : []),
  ], [load, showAll, canRevoke, selected]);
  const hints = useMemo<KeyHint[]>(() => [["j/k", "move"], ["n", "new"], ["x", "revoke"], ["a", showAll ? "active only" : "show all"], ["r", "reload"]], [showAll]);
  useScreen(commands, hints);

  return (
    <div className="grid h-full min-h-0 grid-cols-1 gap-3 md:grid-cols-[minmax(18rem,26rem)_1fr] sm:gap-4">
      <Panel
        title={<>Leases <span className="text-dim">· {visible.length}{hiddenCount > 0 ? ` (+${hiddenCount} ended)` : ""}</span></>}
        actions={
          <>
            <Button size="icon-sm" variant="ghost" onClick={() => void load(false)} aria-label="Reload" title="Reload (r)"><RefreshCw /></Button>
            <Button size="sm" variant="primary" onClick={() => setDialog("new")}><Plus />New</Button>
          </>
        }
        bodyClassName="flex flex-col"
      >
        <label className="flex items-center gap-2 border-b border-border px-4 py-2 text-xs text-muted">
          <Switch checked={showAll} onCheckedChange={setShowAll} aria-label="Show ended leases" />
          Show expired and revoked
        </label>
        <div ref={listRef} role="listbox" aria-label="Leases" className="min-h-0 flex-1 overflow-y-auto p-1.5">
          {leases === null ? (
            <div className="flex justify-center py-10"><Spinner /></div>
          ) : visible.length === 0 ? (
            <Empty icon={<KeyRound />} title={showAll ? "No leases yet" : "No active leases"}>
              A lease grants time-boxed access to some secrets, for <code className="font-mono">autho exec --lease</code> and the daemon. Press <Kbd>n</Kbd> to create one.
            </Empty>
          ) : (
            visible.map((lease) => {
              const status = statusOf(lease, now);
              const active = lease.id === selected?.id;
              return (
                <div
                  key={lease.id}
                  role="option"
                  aria-selected={active}
                  data-id={lease.id}
                  onClick={() => setSelectedId(lease.id)}
                  className={cn(
                    "flex cursor-pointer items-center gap-3 rounded-md border-l-2 px-2.5 py-2 transition-colors",
                    active ? "border-accent bg-selection" : "border-transparent hover:bg-selection/50",
                  )}
                >
                  <span className={cn("text-xs", STATUS_STYLE[status])} aria-hidden>●</span>
                  <div className="min-w-0 flex-1">
                    <div className={cn("truncate text-sm", active ? "text-accent" : "text-text")}>{lease.name}</div>
                    <div className="truncate text-xs text-dim">
                      {status === "active" ? `expires ${relativeTime(lease.expiresAt, now)}` : status === "revoked" ? `revoked ${relativeTime(lease.revokedAt!, now)}` : `expired ${relativeTime(lease.expiresAt, now)}`}
                    </div>
                  </div>
                  <span className="shrink-0 text-xs text-dim">{lease.coverage.length} secret{lease.coverage.length === 1 ? "" : "s"}</span>
                </div>
              );
            })
          )}
        </div>
      </Panel>

      <Panel
        title={selected ? selected.name : "Lease"}
        actions={canRevoke ? <Button size="sm" variant="danger" onClick={() => setDialog("revoke")}>Revoke <Kbd className="border-danger/40 text-danger">x</Kbd></Button> : undefined}
        bodyClassName="overflow-y-auto"
      >
        {selected ? (
          <div className="divide-y divide-border">
            <DetailRow label="Status"><span className={STATUS_STYLE[statusOf(selected, now)]}>{statusOf(selected, now)}</span></DetailRow>
            <DetailRow label="ID"><span className="break-all font-mono text-xs">{selected.id}</span></DetailRow>
            <DetailRow label="Created">{formatDate(selected.createdAt)}</DetailRow>
            <DetailRow label={statusOf(selected, now) === "active" ? "Expires" : "Expired"}>{formatDate(selected.expiresAt)} <span className="text-dim">· {relativeTime(selected.expiresAt, now)}</span></DetailRow>
            {selected.revokedAt ? <DetailRow label="Revoked">{formatDate(selected.revokedAt)}</DetailRow> : null}
            <DetailRow label="Linked secrets">{selected.includeLinks ? "included" : <span className="text-muted">not included</span>}</DetailRow>
            <div className="px-4 py-3.5">
              <div className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted">Covers</div>
              <ul className="flex flex-col gap-1">
                {selected.coverage.map((secret) => {
                  const meta = TYPE_META[secret.type];
                  return (
                    <li key={secret.id} className="flex items-center gap-3 rounded-md bg-panel-alt px-3 py-1.5">
                      <span className={cn("w-3 text-center text-xs", meta.color)}>{meta.glyph}</span>
                      <span className="min-w-0 flex-1 truncate text-sm text-text">{secret.name}</span>
                      {secret.via ? <span className="truncate text-xs text-dim">via {secret.via.name}</span> : null}
                    </li>
                  );
                })}
              </ul>
            </div>
          </div>
        ) : (
          <Empty icon={<KeyRound />} title="Nothing selected" />
        )}
      </Panel>

      <Dialog open={dialog !== null} onOpenChange={(open) => !open && setDialog(null)}>
        {dialog === "new" ? (
          <NewLeaseDialog
            onCreated={(lease) => {
              setDialog(null);
              setShowAll(false);
              setSelectedId(lease.id);
              void load();
            }}
          />
        ) : null}
        {dialog === "revoke" && selected ? (
          <ConfirmDialog
            title={`Revoke "${selected.name}"?`}
            body="Anything using this lease loses access to its secrets right away."
            action="Revoke"
            onConfirm={async () => { setDialog(null); await revoke(); }}
            onCancel={() => setDialog(null)}
          />
        ) : null}
      </Dialog>
    </div>
  );
}

function DetailRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1 px-4 py-3">
      <span className="w-32 shrink-0 text-xs font-semibold uppercase tracking-wider text-muted">{label}</span>
      <span className="min-w-0 flex-1 text-sm text-text">{children}</span>
    </div>
  );
}

function NewLeaseDialog({ onCreated }: { onCreated: (lease: Lease) => void }) {
  const [secrets, setSecrets] = useState<SecretEntry[] | null>(null);
  const [name, setName] = useState("");
  const [ttl, setTtl] = useState("");
  const [includeLinks, setIncludeLinks] = useState(true);
  const [picked, setPicked] = useState<Set<string>>(() => new Set());
  const [query, setQuery] = useState("");
  const [cursor, setCursor] = useState(0);
  const [error, setError] = useState<{ field?: string; message: string } | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    Promise.all([api.secrets(), api.settings()])
      .then(([list, settings]) => {
        setSecrets(list);
        const fallback = settings.preferences.find((p) => p.key === "defaultLeaseTtl")?.value;
        setTtl(typeof fallback === "number" && fallback > 0 ? formatDuration(fallback) : "1h");
      })
      .catch((e) => setError({ message: errorMessage(e) }));
  }, []);

  const candidates = useMemo(() => fuzzyFilter(secrets ?? [], query, (s) => [s.name, s.username, s.url]), [secrets, query]);
  useEffect(() => setCursor(0), [query]);

  const toggle = (id: string) => setPicked((current) => {
    const next = new Set(current);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    return next;
  });

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    const seconds = parseDuration(ttl);
    if (seconds === null || seconds <= 0) return setError({ field: "ttl", message: "Use a duration like 90s, 15m, 2h or 1d" });
    if (seconds > 2_592_000) return setError({ field: "ttl", message: "At most 30 days" });
    if (picked.size === 0) return setError({ field: "secrets", message: "Pick at least one secret" });
    setBusy(true);
    setError(null);
    try {
      const lease = await api.createLease({ name: name.trim() || "web", secrets: [...picked], ttlSeconds: seconds, includeLinks });
      toast.success(`Created lease "${lease.name}"`, { description: `ID ${lease.id} · expires ${relativeTime(lease.expiresAt)}` });
      onCreated(lease);
    } catch (e) {
      setError({ message: errorMessage(e) });
      setBusy(false);
    }
  };

  const fieldError = (field: string) => (error?.field === field ? error.message : undefined);

  return (
    <DialogContent title="New lease" description="Grant time-boxed access to a set of secrets." className="w-[min(94vw,36rem)]">
      <form onSubmit={(e) => void submit(e)} className="flex flex-col gap-4">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-[1fr_9rem]">
          <Field label="Name" htmlFor="lease-name">
            <Input id="lease-name" autoFocus value={name} onChange={(e) => setName(e.target.value)} placeholder="web" maxLength={200} />
          </Field>
          <Field label="Expires after" htmlFor="lease-ttl" error={fieldError("ttl")}>
            <Input id="lease-ttl" value={ttl} onChange={(e) => { setTtl(e.target.value); setError(null); }} placeholder="1h" className="font-mono" aria-invalid={Boolean(fieldError("ttl")) || undefined} />
          </Field>
        </div>

        <Field label={`Secrets${picked.size ? ` · ${picked.size} picked` : ""}`} htmlFor="lease-search" error={fieldError("secrets")}>
          <Input
            id="lease-search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search, then space or enter to pick"
            onKeyDown={(e) => {
              if (e.key === "ArrowDown") {
                e.preventDefault();
                setCursor((c) => Math.min(candidates.length - 1, c + 1));
              } else if (e.key === "ArrowUp") {
                e.preventDefault();
                setCursor((c) => Math.max(0, c - 1));
              } else if ((e.key === "Enter" || (e.key === " " && !query)) && candidates[cursor]) {
                e.preventDefault();
                toggle(candidates[cursor].id);
                setError(null);
              }
            }}
          />
        </Field>
        <div role="listbox" aria-multiselectable aria-label="Secrets" className="-mt-2 max-h-[32vh] overflow-y-auto rounded-md border border-border">
          {secrets === null ? (
            <div className="flex justify-center py-6"><Spinner /></div>
          ) : candidates.length === 0 ? (
            <p className="px-3 py-6 text-center text-sm text-dim">No secrets{query ? " match" : ""}.</p>
          ) : (
            candidates.map((secret, index) => {
              const on = picked.has(secret.id);
              const meta = TYPE_META[secret.type];
              return (
                <button
                  key={secret.id}
                  type="button"
                  role="option"
                  aria-selected={on}
                  onClick={() => { toggle(secret.id); setError(null); }}
                  onMouseEnter={() => setCursor(index)}
                  className={cn("flex w-full cursor-pointer items-center gap-3 border-b border-border px-3 py-2 text-left last:border-b-0", index === cursor && "bg-selection")}
                >
                  <span className={cn("flex size-4 items-center justify-center rounded border", on ? "border-accent bg-accent text-on-accent" : "border-border")}>
                    {on ? <Check className="size-3" /> : null}
                  </span>
                  <span className={cn("w-3 text-center text-xs", meta.color)}>{meta.glyph}</span>
                  <span className="min-w-0 flex-1 truncate text-sm text-text">{secret.name}</span>
                  {secret.linkCount > 0 ? <span className="text-xs text-dim">+{secret.linkCount} linked</span> : null}
                </button>
              );
            })
          )}
        </div>

        <label className="flex items-center gap-3 text-sm text-text">
          <Switch checked={includeLinks} onCheckedChange={setIncludeLinks} aria-label="Include linked secrets" />
          Include linked secrets
        </label>

        {error && !error.field ? <p role="alert" className="rounded-md bg-danger-bg px-3 py-2 text-sm text-danger">✗ {error.message}</p> : null}

        <DialogFooter className="mt-1">
          <Button type="submit" variant="primary" disabled={busy || secrets === null}>
            {busy ? <Spinner className="border-on-accent/30 border-t-on-accent" /> : null}Create lease
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}
