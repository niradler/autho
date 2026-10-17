import { Copy, ExternalLink, Eye, EyeOff, KeyRound, Link2, Pencil, Plus, RefreshCw, Search, Trash2, Unlink } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { toast } from "sonner";

import { Button } from "../components/ui/button.tsx";
import { Dialog, DialogContent, DialogFooter } from "../components/ui/dialog.tsx";
import { Input } from "../components/ui/field.tsx";
import { Empty, Kbd, Panel, Spinner } from "../components/ui/panel.tsx";
import { Tooltip } from "../components/ui/tooltip.tsx";
import { useApp, useScreen, type Command, type KeyHint } from "../context.tsx";
import { api, errorMessage, type LinkedSecret, type SecretDetail, type SecretEntry } from "../lib/api.ts";
import { MASK, TYPE_META, cn, formatDate, formatOtp, fuzzyFilter, hostOf, isHttpUrl, isTypingTarget } from "../lib/utils.ts";
import { SecretForm } from "./secret-form.tsx";

type DialogState =
  | { kind: "new" }
  | { kind: "edit"; secret: SecretDetail }
  | { kind: "delete"; secret: SecretDetail }
  | { kind: "link"; secret: SecretDetail }
  | null;

export function VaultScreen() {
  const app = useApp();
  const [secrets, setSecrets] = useState<SecretEntry[] | null>(null);
  const [query, setQuery] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<SecretDetail | null>(null);
  const [revealed, setRevealed] = useState<{ id: string; value: string } | null>(null);
  const [dialog, setDialog] = useState<DialogState>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const { setModalOpen } = app;

  const load = useCallback(async (quiet = true) => {
    try {
      setSecrets(await api.secrets());
      if (!quiet) toast.success("Reloaded");
    } catch (error) {
      toast.error(errorMessage(error));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    setModalOpen(dialog !== null);
    return () => setModalOpen(false);
  }, [dialog, setModalOpen]);

  const filtered = useMemo(
    () => (secrets ? fuzzyFilter(secrets, query, (s) => [s.name, s.username, s.url, s.description]) : []),
    [secrets, query],
  );

  // Keep a valid selection as the list or the filter changes.
  useEffect(() => {
    if (filtered.length === 0) {
      setSelectedId(null);
    } else if (!filtered.some((s) => s.id === selectedId)) {
      setSelectedId(filtered[0]!.id);
    }
  }, [filtered, selectedId]);

  const loadDetail = useCallback(async (id: string) => {
    try {
      const next = await api.secret(id);
      setDetail((current) => (current === null || current.id === id || next.id === id ? next : current));
    } catch (error) {
      toast.error(errorMessage(error));
    }
  }, []);

  useEffect(() => {
    setRevealed(null);
    if (!selectedId) {
      setDetail(null);
      return;
    }
    setDetail((current) => (current?.id === selectedId ? current : null));
    void loadDetail(selectedId);
  }, [selectedId, loadDetail]);

  // Revealed values hide again after the reveal preference (0 keeps them until hidden).
  useEffect(() => {
    if (!revealed || app.prefs.revealSeconds <= 0) return;
    const timer = window.setTimeout(() => setRevealed(null), app.prefs.revealSeconds * 1000);
    return () => window.clearTimeout(timer);
  }, [revealed, app.prefs.revealSeconds]);

  // Scroll the selected row into view when moving with the keyboard.
  useEffect(() => {
    if (!selectedId) return;
    listRef.current?.querySelector(`[data-id="${CSS.escape(selectedId)}"]`)?.scrollIntoView({ block: "nearest" });
  }, [selectedId]);

  const selected = detail && detail.id === selectedId ? detail : null;
  const entry = filtered.find((s) => s.id === selectedId) ?? null;

  const move = useCallback((delta: number | "top" | "bottom") => {
    if (filtered.length === 0) return;
    const index = filtered.findIndex((s) => s.id === selectedId);
    const next = delta === "top" ? 0 : delta === "bottom" ? filtered.length - 1 : Math.min(filtered.length - 1, Math.max(0, index + delta));
    setSelectedId(filtered[next]!.id);
  }, [filtered, selectedId]);

  const jumpTo = useCallback((id: string) => {
    setQuery("");
    setSelectedId(id);
  }, []);

  // ── Actions ────────────────────────────────────────────────────

  const copyValue = useCallback(async (target: SecretEntry | null = entry) => {
    if (!target) return;
    try {
      if (target.type === "otp") {
        const { code } = await api.otp(target.id, true);
        await app.copy("Code", code, true);
      } else {
        const { value } = await api.reveal(target.id);
        await app.copy(target.type === "note" ? "Note" : "Password", value, true);
      }
    } catch (error) {
      toast.error(errorMessage(error));
    }
  }, [entry, app]);

  const copyUsername = useCallback(() => {
    if (!entry) return;
    if (!entry.username) return void toast(`${entry.name} has no username`);
    void app.copy("Username", entry.username);
  }, [entry, app]);

  const copyUrl = useCallback(() => {
    if (!entry) return;
    if (!entry.url) return void toast(`${entry.name} has no URL`);
    void app.copy("URL", entry.url);
  }, [entry, app]);

  const openUrl = useCallback(() => {
    if (!entry) return;
    if (entry.type === "otp") return void copyValue(entry);
    if (!isHttpUrl(entry.url)) return void toast(`${entry.name} has no URL to open`);
    window.open(entry.url, "_blank", "noopener,noreferrer");
  }, [entry, copyValue]);

  const toggleReveal = useCallback(async () => {
    if (!entry || entry.type === "otp") return;
    if (revealed?.id === entry.id) return setRevealed(null);
    try {
      const { value } = await api.reveal(entry.id);
      setRevealed({ id: entry.id, value });
    } catch (error) {
      toast.error(errorMessage(error));
    }
  }, [entry, revealed]);

  const copyLinkedOtp = useCallback(async () => {
    if (!selected) return;
    const otp = selected.type === "otp" ? selected : selected.links.find((l) => l.type === "otp");
    if (!otp) return void toast(`${selected.name} has no linked OTP`);
    try {
      const { code } = await api.otp(otp.id, true);
      await app.copy(`${otp.name} code`, code, true);
    } catch (error) {
      toast.error(errorMessage(error));
    }
  }, [selected, app]);

  const afterChange = useCallback(async (focusId?: string) => {
    await load();
    if (focusId) {
      setSelectedId(focusId);
      void loadDetail(focusId);
    }
  }, [load, loadDetail]);

  const openDialog = useCallback((kind: "edit" | "delete" | "link") => {
    if (selected) setDialog({ kind, secret: selected });
  }, [selected]);

  // ── Keys (TUI bindings) ────────────────────────────────────────

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.defaultPrevented || app.paletteOpen || app.modalOpen || event.ctrlKey || event.metaKey || event.altKey) return;
      if (isTypingTarget(event.target)) return;
      const actions: Record<string, () => void> = {
        ArrowDown: () => move(1),
        j: () => move(1),
        ArrowUp: () => move(-1),
        k: () => move(-1),
        g: () => move("top"),
        G: () => move("bottom"),
        Home: () => move("top"),
        End: () => move("bottom"),
        "/": () => searchRef.current?.focus(),
        n: () => setDialog({ kind: "new" }),
        r: () => void load(false),
        Enter: () => void copyValue(),
        c: () => void copyValue(),
        u: copyUsername,
        w: copyUrl,
        s: () => void toggleReveal(),
        " ": () => void toggleReveal(),
        o: openUrl,
        e: () => openDialog("edit"),
        t: () => void copyLinkedOtp(),
        d: () => openDialog("delete"),
        Delete: () => openDialog("delete"),
        L: () => openDialog("link"),
        Escape: () => {
          if (revealed) setRevealed(null);
          else if (query) setQuery("");
        },
      };
      const action = actions[event.key];
      if (!action) return;
      event.preventDefault();
      action();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [app.paletteOpen, app.modalOpen, move, load, copyValue, copyUsername, copyUrl, toggleReveal, openUrl, openDialog, copyLinkedOtp, revealed, query]);

  // ── Palette and status bar ─────────────────────────────────────

  const commands = useMemo<Command[]>(() => {
    const list: Command[] = [];
    if (entry) {
      const name = entry.name;
      if (entry.type === "otp") list.push({ id: "copy", title: `Copy code · ${name}`, group: "Selected", hint: "c", run: () => void copyValue(entry) });
      else list.push({ id: "copy", title: `Copy ${entry.type === "note" ? "note" : "password"} · ${name}`, group: "Selected", hint: "c", run: () => void copyValue(entry) });
      if (entry.username) list.push({ id: "user", title: `Copy username · ${name}`, group: "Selected", hint: "u", run: copyUsername });
      if (entry.url) list.push({ id: "url", title: `Copy URL · ${name}`, group: "Selected", hint: "w", run: copyUrl });
      if (isHttpUrl(entry.url)) list.push({ id: "open", title: `Open ${hostOf(entry.url)}`, group: "Selected", hint: "o", run: openUrl });
      if (entry.type !== "otp") list.push({ id: "reveal", title: revealed?.id === entry.id ? "Hide value" : "Reveal value", group: "Selected", hint: "s", run: () => void toggleReveal() });
      if (selected?.links.some((l) => l.type === "otp")) list.push({ id: "otp", title: "Copy linked OTP code", group: "Selected", hint: "t", run: () => void copyLinkedOtp() });
      list.push(
        { id: "edit", title: `Edit · ${name}`, group: "Selected", hint: "e", run: () => openDialog("edit") },
        { id: "link", title: `Link secrets · ${name}`, group: "Selected", hint: "L", run: () => openDialog("link") },
        { id: "delete", title: `Delete · ${name}`, group: "Selected", hint: "d", run: () => openDialog("delete") },
      );
    }
    list.push(
      { id: "new", title: "New secret", group: "Vault", hint: "n", run: () => setDialog({ kind: "new" }) },
      { id: "search", title: "Search secrets", group: "Vault", hint: "/", run: () => searchRef.current?.focus() },
      { id: "reload", title: "Reload", group: "Vault", hint: "r", run: () => void load(false) },
    );
    for (const linked of [...(selected?.links ?? []), ...(selected?.linkedFrom ?? [])]) {
      list.push({ id: `linked:${linked.id}`, title: `Go to ${linked.name}`, group: "Linked", run: () => jumpTo(linked.id) });
    }
    for (const secret of secrets ?? []) {
      list.push({ id: `jump:${secret.id}`, title: secret.name, group: "Jump to", keywords: [secret.username, secret.url].filter(Boolean).join(" "), run: () => jumpTo(secret.id) });
    }
    return list;
  }, [entry, selected, secrets, revealed, copyValue, copyUsername, copyUrl, openUrl, toggleReveal, copyLinkedOtp, openDialog, load, jumpTo]);

  const hints = useMemo<KeyHint[]>(() => {
    const base: KeyHint[] = [["↑↓", "move"], ["/", "search"], ["n", "new"]];
    if (!entry) return base;
    return [...base, ["c", entry.type === "otp" ? "copy code" : "copy"], ["s", "reveal"], ["e", "edit"], ["d", "delete"], ["L", "link"]];
  }, [entry]);

  useScreen(commands, hints);

  // ── Render ─────────────────────────────────────────────────────

  return (
    <div className="grid h-full min-h-0 grid-cols-1 gap-3 md:grid-cols-[minmax(16rem,22rem)_1fr] sm:gap-4">
      <Panel
        title={secrets ? `Secrets · ${query ? `${filtered.length}/${secrets.length}` : secrets.length}` : "Secrets"}
        actions={
          <>
            <Tooltip content="Reload (r)">
              <Button variant="ghost" size="icon-sm" onClick={() => void load(false)} aria-label="Reload"><RefreshCw /></Button>
            </Tooltip>
            <Tooltip content="New secret (n)">
              <Button variant="ghost" size="icon-sm" onClick={() => setDialog({ kind: "new" })} aria-label="New secret"><Plus /></Button>
            </Tooltip>
          </>
        }
        bodyClassName="flex flex-col"
        className={cn(selected ? "hidden md:flex" : "flex")}
      >
        <div className="relative border-b border-border p-2">
          <Search className="pointer-events-none absolute left-4.5 top-1/2 size-4 -translate-y-1/2 text-dim" />
          <Input
            ref={searchRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search"
            aria-label="Search secrets"
            className="pl-8"
            onKeyDown={(e) => {
              if (e.key === "ArrowDown" || e.key === "ArrowUp") {
                e.preventDefault();
                move(e.key === "ArrowDown" ? 1 : -1);
              } else if (e.key === "Enter") {
                e.preventDefault();
                e.currentTarget.blur();
              } else if (e.key === "Escape") {
                e.preventDefault();
                if (query) setQuery("");
                else e.currentTarget.blur();
              }
            }}
          />
          {!query ? <Kbd className="pointer-events-none absolute right-4 top-1/2 -translate-y-1/2">/</Kbd> : null}
        </div>
        <div ref={listRef} role="listbox" aria-label="Secrets" className="min-h-0 flex-1 overflow-y-auto p-1.5">
          {secrets === null ? (
            <div className="flex justify-center py-10"><Spinner /></div>
          ) : secrets.length === 0 ? (
            <Empty icon={<KeyRound />} title="Your vault is empty">
              Press <Kbd>n</Kbd> to add your first secret.
            </Empty>
          ) : filtered.length === 0 ? (
            <Empty icon={<Search />} title="No matches">Nothing matches “{query}”.</Empty>
          ) : (
            filtered.map((secret) => (
              <SecretRow key={secret.id} secret={secret} active={secret.id === selectedId} onSelect={() => setSelectedId(secret.id)} onCopy={() => void copyValue(secret)} />
            ))
          )}
        </div>
      </Panel>

      <div className={cn("min-h-0", selected ? "flex" : "hidden md:flex")}>
        {selected ? (
          <SecretPane
            secret={selected}
            revealed={revealed?.id === selected.id ? revealed.value : null}
            onBack={() => setSelectedId(null)}
            onCopy={() => void copyValue(selected)}
            onCopyLinkedOtp={() => void copyLinkedOtp()}
            onCopyUsername={copyUsername}
            onCopyUrl={copyUrl}
            onOpen={openUrl}
            onReveal={() => void toggleReveal()}
            onEdit={() => openDialog("edit")}
            onDelete={() => openDialog("delete")}
            onLink={() => openDialog("link")}
            onGoTo={jumpTo}
          />
        ) : (
          <Panel className="flex-1">
            {secrets && secrets.length > 0 && entry ? (
              <div className="flex h-full items-center justify-center"><Spinner /></div>
            ) : (
              <Empty icon={<KeyRound />} title="Nothing selected">Pick a secret on the left, or press <Kbd>n</Kbd> to add one.</Empty>
            )}
          </Panel>
        )}
      </div>

      <Dialog open={dialog?.kind === "new" || dialog?.kind === "edit"} onOpenChange={(open) => !open && setDialog(null)}>
        {dialog?.kind === "new" || dialog?.kind === "edit" ? (
          <SecretForm
            secret={dialog.kind === "edit" ? dialog.secret : null}
            existingNames={(secrets ?? []).map((s) => s.name)}
            onDone={(saved) => {
              setDialog(null);
              void afterChange(saved.id);
            }}
          />
        ) : null}
      </Dialog>

      <Dialog open={dialog?.kind === "delete"} onOpenChange={(open) => !open && setDialog(null)}>
        {dialog?.kind === "delete" ? (
          <DeleteDialog
            secret={dialog.secret}
            onDone={() => {
              setDialog(null);
              void afterChange();
            }}
            onCancel={() => setDialog(null)}
          />
        ) : null}
      </Dialog>

      <Dialog open={dialog?.kind === "link"} onOpenChange={(open) => !open && setDialog(null)}>
        {dialog?.kind === "link" ? (
          <LinkDialog
            secret={dialog.secret}
            secrets={secrets ?? []}
            onChanged={() => void afterChange(dialog.secret.id)}
          />
        ) : null}
      </Dialog>
    </div>
  );
}

function SecretRow({ secret, active, onSelect, onCopy }: { secret: SecretEntry; active: boolean; onSelect: () => void; onCopy: () => void }) {
  const meta = TYPE_META[secret.type];
  const sub = secret.username ?? (secret.url ? hostOf(secret.url) : meta.label);
  return (
    <div
      role="option"
      aria-selected={active}
      data-id={secret.id}
      onClick={onSelect}
      onDoubleClick={onCopy}
      className={cn(
        "group flex cursor-pointer items-center gap-3 rounded-md border-l-2 px-2.5 py-2 transition-colors",
        active ? "border-accent bg-selection" : "border-transparent hover:bg-selection/50",
      )}
    >
      <span className={cn("w-3 shrink-0 text-center text-xs", meta.color)} aria-hidden>{meta.glyph}</span>
      <div className="min-w-0 flex-1">
        <div className={cn("truncate text-sm", active ? "text-accent" : "text-text")}>{secret.name}</div>
        <div className="truncate text-xs text-dim">{sub}</div>
      </div>
      {secret.linkCount > 0 ? (
        <span className="flex shrink-0 items-center gap-0.5 text-xs text-dim" title={`${secret.linkCount} linked`}>
          <Link2 className="size-3" />{secret.linkCount}
        </span>
      ) : null}
    </div>
  );
}

function SecretPane(props: {
  secret: SecretDetail;
  revealed: string | null;
  onBack: () => void;
  onCopy: () => void;
  onCopyLinkedOtp: () => void;
  onCopyUsername: () => void;
  onCopyUrl: () => void;
  onOpen: () => void;
  onReveal: () => void;
  onEdit: () => void;
  onDelete: () => void;
  onLink: () => void;
  onGoTo: (id: string) => void;
}) {
  const { secret, revealed } = props;
  const meta = TYPE_META[secret.type];
  const linkedOtp = secret.links.find((l) => l.type === "otp");

  return (
    <Panel
      className="flex-1"
      focused
      title={
        <span className="flex items-center gap-2 normal-case tracking-normal">
          <button type="button" onClick={props.onBack} className="cursor-pointer text-dim hover:text-text md:hidden" aria-label="Back">←</button>
          <span className={cn("text-xs", meta.color)}>{meta.glyph}</span>
          <span className="text-sm text-text">{secret.name}</span>
          <span className="rounded bg-chip px-1.5 py-0.5 text-[11px] font-normal text-muted">{meta.label}</span>
        </span>
      }
      actions={
        <>
          <Tooltip content="Edit (e)"><Button variant="ghost" size="icon-sm" onClick={props.onEdit} aria-label="Edit"><Pencil /></Button></Tooltip>
          <Tooltip content="Link secrets (shift+L)"><Button variant="ghost" size="icon-sm" onClick={props.onLink} aria-label="Link secrets"><Link2 /></Button></Tooltip>
          <Tooltip content="Delete (d)"><Button variant="ghost" size="icon-sm" onClick={props.onDelete} aria-label="Delete" className="hover:text-danger"><Trash2 /></Button></Tooltip>
        </>
      }
      bodyClassName="overflow-y-auto"
    >
      <dl className="flex flex-col divide-y divide-border">
        {secret.type === "otp" ? (
          <Row label="Code" keyHint="c">
            <OtpCode id={secret.id} onCopy={props.onCopy} />
          </Row>
        ) : (
          <Row
            label={secret.type === "note" ? "Note" : "Password"}
            keyHint="c"
            actions={
              <>
                <Tooltip content={revealed ? "Hide (s)" : "Reveal (s)"}>
                  <Button variant="ghost" size="icon-sm" onClick={props.onReveal} aria-label={revealed ? "Hide" : "Reveal"}>{revealed ? <EyeOff /> : <Eye />}</Button>
                </Tooltip>
                <Tooltip content="Copy (c)"><Button variant="ghost" size="icon-sm" onClick={props.onCopy} aria-label="Copy"><Copy /></Button></Tooltip>
              </>
            }
          >
            {revealed !== null ? (
              <pre className={cn("whitespace-pre-wrap break-all font-mono text-sm text-revealed", secret.type === "note" && "max-h-80 overflow-y-auto")}>{revealed}</pre>
            ) : (
              <span className="font-mono text-sm tracking-wider text-muted">{MASK}</span>
            )}
          </Row>
        )}

        {secret.username ? (
          <Row label="Username" keyHint="u" actions={<Tooltip content="Copy (u)"><Button variant="ghost" size="icon-sm" onClick={props.onCopyUsername} aria-label="Copy username"><Copy /></Button></Tooltip>}>
            <span className="break-all font-mono text-sm text-text">{secret.username}</span>
          </Row>
        ) : null}

        {secret.url ? (
          <Row
            label="URL"
            keyHint="w"
            actions={
              <>
                {isHttpUrl(secret.url) ? <Tooltip content="Open (o)"><Button variant="ghost" size="icon-sm" onClick={props.onOpen} aria-label="Open URL"><ExternalLink /></Button></Tooltip> : null}
                <Tooltip content="Copy (w)"><Button variant="ghost" size="icon-sm" onClick={props.onCopyUrl} aria-label="Copy URL"><Copy /></Button></Tooltip>
              </>
            }
          >
            <span className="break-all text-sm text-info">{secret.url}</span>
          </Row>
        ) : null}

        {linkedOtp ? (
          <Row label={`OTP · ${linkedOtp.name}`} keyHint="t">
            <OtpCode id={linkedOtp.id} onCopy={props.onCopyLinkedOtp} />
          </Row>
        ) : null}

        {secret.description ? (
          <Row label={secret.type === "password" ? "Notes" : "Description"}>
            <p className="whitespace-pre-wrap break-words text-sm text-text/90">{secret.description}</p>
          </Row>
        ) : null}

        {secret.links.length > 0 || secret.linkedFrom.length > 0 ? (
          <Row label="Linked">
            <div className="flex flex-wrap gap-1.5">
              {secret.links.map((l) => <LinkChip key={`to:${l.id}`} secret={l} onClick={() => props.onGoTo(l.id)} />)}
              {secret.linkedFrom.map((l) => <LinkChip key={`from:${l.id}`} secret={l} from onClick={() => props.onGoTo(l.id)} />)}
            </div>
          </Row>
        ) : null}

        <Row label="History">
          <div className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-xs">
            <span className="text-dim">Created</span><span className="text-muted">{formatDate(secret.createdAt)}</span>
            <span className="text-dim">Updated</span><span className="text-muted">{formatDate(secret.updatedAt)}</span>
          </div>
        </Row>
      </dl>
    </Panel>
  );
}

function Row({ label, keyHint, actions, children }: { label: string; keyHint?: string; actions?: ReactNode; children: ReactNode }) {
  return (
    <div className="group flex items-start gap-4 px-4 py-3.5">
      <div className="min-w-0 flex-1">
        <dt className="mb-1.5 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-dim">
          {label}
          {keyHint ? <Kbd className="opacity-0 transition-opacity group-hover:opacity-100">{keyHint}</Kbd> : null}
        </dt>
        <dd className="min-w-0">{children}</dd>
      </div>
      {actions ? <div className="flex shrink-0 items-center gap-0.5 pt-4">{actions}</div> : null}
    </div>
  );
}

function LinkChip({ secret, from, onClick }: { secret: LinkedSecret; from?: boolean; onClick: () => void }) {
  const meta = TYPE_META[secret.type];
  return (
    <button
      type="button"
      onClick={onClick}
      title={from ? `${secret.name} links to this` : `Linked under this`}
      className="flex cursor-pointer items-center gap-1.5 rounded-md border border-border bg-chip px-2 py-1 text-xs text-text transition-colors hover:border-accent hover:text-accent"
    >
      <span className={meta.color}>{meta.glyph}</span>
      {from ? <span className="text-dim">↖</span> : null}
      {secret.name}
    </button>
  );
}

/** Live TOTP code with a countdown that turns red in the last 5 seconds, like the TUI. */
function OtpCode({ id, onCopy }: { id: string; onCopy: () => void }) {
  const [otp, setOtp] = useState<{ code: string; expiresAt: number } | null>(null);
  const [now, setNow] = useState(Date.now());
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    let timer = 0;
    const fetchCode = async () => {
      try {
        const next = await api.otp(id);
        if (cancelled) return;
        const expiresAt = Date.parse(next.expiresAt);
        setOtp({ code: next.code, expiresAt });
        setError("");
        timer = window.setTimeout(fetchCode, Math.max(500, expiresAt - Date.now() + 250));
      } catch (e) {
        if (!cancelled) setError(errorMessage(e));
      }
    };
    void fetchCode();
    const tick = window.setInterval(() => setNow(Date.now()), 1000);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
      window.clearInterval(tick);
    };
  }, [id]);

  if (error) return <span className="text-sm text-danger">{error}</span>;
  if (!otp) return <Spinner />;
  const left = Math.max(0, Math.ceil((otp.expiresAt - now) / 1000));
  return (
    <div className="flex items-center gap-4">
      <button type="button" onClick={onCopy} className="cursor-pointer font-mono text-2xl tracking-[0.15em] text-success hover:text-revealed" title="Copy code">
        {formatOtp(otp.code)}
      </button>
      <span className={cn("flex items-center gap-1.5 font-mono text-xs", left <= 5 ? "text-danger" : "text-muted")}>
        <CountdownRing seconds={left} />
        {left}s
      </span>
      <Button variant="ghost" size="icon-sm" onClick={onCopy} aria-label="Copy code"><Copy /></Button>
    </div>
  );
}

function CountdownRing({ seconds, period = 30 }: { seconds: number; period?: number }) {
  const r = 7;
  const c = 2 * Math.PI * r;
  return (
    <svg viewBox="0 0 18 18" className="size-4 -rotate-90" aria-hidden>
      <circle cx="9" cy="9" r={r} fill="none" stroke="currentColor" strokeOpacity="0.2" strokeWidth="2" />
      <circle cx="9" cy="9" r={r} fill="none" stroke="currentColor" strokeWidth="2" strokeDasharray={c} strokeDashoffset={c * (1 - Math.min(1, seconds / period))} className="transition-[stroke-dashoffset] duration-1000 ease-linear" />
    </svg>
  );
}

/** y deletes, a deletes with linked secrets, n/esc cancels — the TUI's confirm. */
function DeleteDialog({ secret, onDone, onCancel }: { secret: SecretDetail; onDone: () => void; onCancel: () => void }) {
  const [busy, setBusy] = useState(false);
  const linked = secret.links;

  const remove = useCallback(async (withLinked: boolean) => {
    setBusy(true);
    try {
      const result = await api.deleteSecret(secret.id, withLinked);
      const extra = result.removedLinked.length ? ` and ${result.removedLinked.length} linked` : "";
      toast.success(`Deleted ${result.name}${extra}`, {
        description: result.keptLinked.length ? `Kept ${result.keptLinked.map((l) => l.name).join(", ")} (linked elsewhere)` : undefined,
      });
      onDone();
    } catch (error) {
      toast.error(errorMessage(error));
      setBusy(false);
    }
  }, [secret.id, onDone]);

  return (
    <DialogContent
      danger
      title={`Delete ${secret.name}?`}
      description="This can't be undone."
      onKeyDown={(e) => {
        if (busy) return;
        if (e.key === "y") void remove(false);
        else if (e.key === "a" && linked.length > 0) void remove(true);
        else if (e.key === "n") onCancel();
      }}
    >
      {linked.length > 0 ? (
        <div className="text-sm text-muted">
          It links to {linked.length === 1 ? "one secret" : `${linked.length} secrets`}:
          <div className="mt-2 flex flex-wrap gap-1.5">
            {linked.map((l) => (
              <span key={l.id} className="flex items-center gap-1.5 rounded-md bg-chip px-2 py-1 text-xs text-text">
                <span className={TYPE_META[l.type].color}>{TYPE_META[l.type].glyph}</span>{l.name}
              </span>
            ))}
          </div>
          <p className="mt-2 text-xs text-dim">Linked secrets still used by another secret are kept.</p>
        </div>
      ) : null}
      <DialogFooter>
        <Button variant="ghost" onClick={onCancel} disabled={busy}>Cancel <Kbd>n</Kbd></Button>
        {linked.length > 0 ? (
          <Button variant="danger" onClick={() => void remove(true)} disabled={busy}>Delete with linked <Kbd>a</Kbd></Button>
        ) : null}
        <Button variant="danger" onClick={() => void remove(false)} disabled={busy} autoFocus>
          {busy ? <Spinner /> : null}Delete <Kbd>y</Kbd>
        </Button>
      </DialogFooter>
    </DialogContent>
  );
}

/** Shift+L: link other secrets under this one, or unlink them. */
function LinkDialog({ secret, secrets, onChanged }: { secret: SecretDetail; secrets: SecretEntry[]; onChanged: () => void }) {
  const [query, setQuery] = useState("");
  const [linkedIds, setLinkedIds] = useState(() => new Set(secret.links.map((l) => l.id)));
  const [busy, setBusy] = useState<string | null>(null);
  const [cursor, setCursor] = useState(0);

  const candidates = useMemo(
    () => fuzzyFilter(secrets.filter((s) => s.id !== secret.id), query, (s) => [s.name, s.username, s.url]),
    [secrets, secret.id, query],
  );

  useEffect(() => setCursor(0), [query]);

  const toggle = async (target: SecretEntry) => {
    if (busy) return;
    setBusy(target.id);
    const linked = linkedIds.has(target.id);
    try {
      if (linked) await api.unlink(secret.id, target.id);
      else await api.link(secret.id, target.id);
      setLinkedIds((current) => {
        const next = new Set(current);
        if (linked) next.delete(target.id);
        else next.add(target.id);
        return next;
      });
      toast.success(linked ? `Unlinked ${target.name}` : `Linked ${target.name} under ${secret.name}`);
      onChanged();
    } catch (error) {
      toast.error(errorMessage(error));
    } finally {
      setBusy(null);
    }
  };

  return (
    <DialogContent title={`Link secrets · ${secret.name}`} description="Linked secrets travel with this one in leases and show on its page." className="w-[min(92vw,34rem)]">
      <Input
        autoFocus
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        placeholder="Search secrets"
        aria-label="Search secrets to link"
        onKeyDown={(e) => {
          if (e.key === "ArrowDown") {
            e.preventDefault();
            setCursor((c) => Math.min(candidates.length - 1, c + 1));
          } else if (e.key === "ArrowUp") {
            e.preventDefault();
            setCursor((c) => Math.max(0, c - 1));
          } else if (e.key === "Enter" && candidates[cursor]) {
            e.preventDefault();
            void toggle(candidates[cursor]);
          }
        }}
      />
      <div className="mt-3 max-h-[45vh] overflow-y-auto rounded-md border border-border">
        {candidates.length === 0 ? (
          <p className="px-3 py-6 text-center text-sm text-dim">No other secrets{query ? " match" : ""}.</p>
        ) : (
          candidates.map((candidate, index) => {
            const linked = linkedIds.has(candidate.id);
            const meta = TYPE_META[candidate.type];
            return (
              <button
                key={candidate.id}
                type="button"
                onClick={() => void toggle(candidate)}
                onMouseEnter={() => setCursor(index)}
                disabled={busy !== null}
                className={cn(
                  "flex w-full cursor-pointer items-center gap-3 border-b border-border px-3 py-2 text-left last:border-b-0",
                  index === cursor ? "bg-selection" : "",
                )}
              >
                <span className={cn("w-3 text-center text-xs", meta.color)}>{meta.glyph}</span>
                <span className="min-w-0 flex-1 truncate text-sm text-text">{candidate.name}</span>
                {busy === candidate.id ? (
                  <Spinner />
                ) : linked ? (
                  <span className="flex items-center gap-1 text-xs text-success"><Unlink className="size-3.5" />linked</span>
                ) : (
                  <span className="text-xs text-dim">link</span>
                )}
              </button>
            );
          })
        )}
      </div>
      <p className="mt-2 text-xs text-dim"><Kbd>↑↓</Kbd> move · <Kbd>enter</Kbd> link / unlink · <Kbd>esc</Kbd> done</p>
    </DialogContent>
  );
}
