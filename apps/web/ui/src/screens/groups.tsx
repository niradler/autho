import { Check, FolderOpen, FolderPlus, Folders, Pencil, Plus, RefreshCw, Search, Trash2 } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { toast } from "sonner";

import { ConfirmDialog } from "../components/confirm-dialog.tsx";
import { Button } from "../components/ui/button.tsx";
import { Dialog, DialogContent, DialogFooter } from "../components/ui/dialog.tsx";
import { Field, Input } from "../components/ui/field.tsx";
import { Empty, Kbd, Panel, Spinner } from "../components/ui/panel.tsx";
import { Tooltip } from "../components/ui/tooltip.tsx";
import { useApp, useScreen, type Command, type KeyHint } from "../context.tsx";
import { UNGROUPED_LABEL, api, errorMessage, type Group, type SecretEntry } from "../lib/api.ts";
import { TYPE_META, cn, formatDate, fuzzyFilter, isTypingTarget } from "../lib/utils.ts";

/** A list row: a real group, or the "(ungrouped)" row (null id) for secrets in no group. */
type Row = { id: string | null; name: string; count: number; createdAt: string | null };

type DialogState = { kind: "new" } | { kind: "rename"; row: Row } | { kind: "delete"; row: Row } | { kind: "add"; row: Row } | null;

export function GroupsScreen() {
  const app = useApp();
  const [groups, setGroups] = useState<Group[] | null>(null);
  const [secrets, setSecrets] = useState<SecretEntry[]>([]);
  const [query, setQuery] = useState("");
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [dialog, setDialog] = useState<DialogState>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const { setModalOpen } = app;

  const load = useCallback(async (quiet = true) => {
    try {
      const [nextGroups, nextSecrets] = await Promise.all([api.groups(), api.secrets()]);
      setGroups(nextGroups);
      setSecrets(nextSecrets);
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

  const rows = useMemo<Row[]>(() => {
    if (!groups) return [];
    const matched: Row[] = fuzzyFilter(groups, query, (g) => [g.name]).map((g) => ({ id: g.id, name: g.name, count: g.secretCount, createdAt: g.createdAt }));
    const ungrouped: Row = { id: null, name: UNGROUPED_LABEL, count: secrets.filter((s) => s.groupId === null).length, createdAt: null };
    return query && fuzzyFilter([ungrouped], query, (r) => [r.name]).length === 0 ? matched : [...matched, ungrouped];
  }, [groups, secrets, query]);

  const keyOf = (row: Row) => row.id ?? "ungrouped";

  // Keep a valid selection as the list or the filter changes.
  useEffect(() => {
    if (rows.length === 0) setSelectedKey(null);
    else if (!rows.some((r) => keyOf(r) === selectedKey)) setSelectedKey(keyOf(rows[0]!));
  }, [rows, selectedKey]);

  useEffect(() => {
    if (!selectedKey) return;
    listRef.current?.querySelector(`[data-id="${CSS.escape(selectedKey)}"]`)?.scrollIntoView({ block: "nearest" });
  }, [selectedKey]);

  const selected = rows.find((r) => keyOf(r) === selectedKey) ?? null;
  const members = useMemo(() => (selected ? secrets.filter((s) => s.groupId === selected.id) : []), [selected, secrets]);

  const move = useCallback((delta: number | "top" | "bottom") => {
    if (rows.length === 0) return;
    const index = rows.findIndex((r) => keyOf(r) === selectedKey);
    const next = delta === "top" ? 0 : delta === "bottom" ? rows.length - 1 : Math.min(rows.length - 1, Math.max(0, index + delta));
    setSelectedKey(keyOf(rows[next]!));
  }, [rows, selectedKey]);

  const open = useCallback((row: Row | null = selected) => {
    if (row) app.openGroup({ id: row.id, name: row.name });
  }, [selected, app]);

  const edit = useCallback((kind: "rename" | "delete" | "add") => {
    if (!selected) return;
    if (selected.id === null) return void toast(kind === "add" ? "Pick a group to add secrets to" : `${UNGROUPED_LABEL} can't be ${kind === "rename" ? "renamed" : "deleted"}`);
    setDialog({ kind, row: selected });
  }, [selected]);

  const remove = useCallback(async (row: Row) => {
    try {
      const result = await api.deleteGroup(row.id!);
      toast.success(`Deleted group "${result.name}"`, { description: `${result.ungrouped} secret${result.ungrouped === 1 ? "" : "s"} ungrouped` });
      setDialog(null);
      await load();
    } catch (error) {
      toast.error(errorMessage(error));
    }
  }, [load]);

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
        a: () => edit("add"),
        e: () => edit("rename"),
        x: () => edit("delete"),
        d: () => edit("delete"),
        Delete: () => edit("delete"),
        r: () => void load(false),
        Enter: () => open(),
        Escape: () => {
          if (query) setQuery("");
        },
      };
      const action = actions[event.key];
      if (!action) return;
      event.preventDefault();
      action();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [app.paletteOpen, app.modalOpen, move, edit, load, open, query]);

  // ── Palette and status bar ─────────────────────────────────────

  const commands = useMemo<Command[]>(() => {
    const list: Command[] = [];
    if (selected) {
      list.push({ id: "open", title: `Show secrets · ${selected.name}`, group: "Selected", hint: "enter", run: () => open(selected) });
      if (selected.id !== null) {
        list.push(
          { id: "add", title: `Add secrets · ${selected.name}`, group: "Selected", hint: "a", run: () => edit("add") },
          { id: "rename", title: `Rename · ${selected.name}`, group: "Selected", hint: "e", run: () => edit("rename") },
          { id: "delete", title: `Delete · ${selected.name}`, group: "Selected", hint: "x", run: () => edit("delete") },
        );
      }
    }
    list.push(
      { id: "new", title: "New group", group: "Groups", hint: "n", run: () => setDialog({ kind: "new" }) },
      { id: "search", title: "Search groups", group: "Groups", hint: "/", run: () => searchRef.current?.focus() },
      { id: "reload", title: "Reload", group: "Groups", hint: "r", run: () => void load(false) },
    );
    return list;
  }, [selected, open, edit, load]);

  const hints = useMemo<KeyHint[]>(() => {
    const base: KeyHint[] = [["↑↓", "move"], ["/", "search"], ["n", "new"]];
    if (!selected) return base;
    return [...base, ["enter", "show secrets"], ...(selected.id === null ? [] : ([["a", "add secrets"], ["e", "rename"], ["x", "delete"]] as KeyHint[]))];
  }, [selected]);

  useScreen(commands, hints);

  // ── Render ─────────────────────────────────────────────────────

  const groupCount = groups?.length ?? 0;

  return (
    <div className="grid h-full min-h-0 grid-cols-1 gap-3 md:grid-cols-[minmax(16rem,22rem)_1fr] sm:gap-4">
      <Panel
        title={groups ? `Groups · ${groupCount}` : "Groups"}
        actions={
          <>
            <Tooltip content="Reload (r)">
              <Button variant="ghost" size="icon-sm" onClick={() => void load(false)} aria-label="Reload"><RefreshCw /></Button>
            </Tooltip>
            <Tooltip content="New group (n)">
              <Button variant="ghost" size="icon-sm" onClick={() => setDialog({ kind: "new" })} aria-label="New group"><Plus /></Button>
            </Tooltip>
          </>
        }
        bodyClassName="flex flex-col"
      >
        <div className="relative border-b border-border p-2">
          <Search className="pointer-events-none absolute left-4.5 top-1/2 size-4 -translate-y-1/2 text-dim" />
          <Input
            ref={searchRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search"
            aria-label="Search groups"
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
        <div ref={listRef} role="listbox" aria-label="Groups" className="min-h-0 flex-1 overflow-y-auto p-1.5">
          {groups === null ? (
            <div className="flex justify-center py-10"><Spinner /></div>
          ) : rows.length === 0 ? (
            <Empty icon={<Search />} title="No matches">Nothing matches “{query}”.</Empty>
          ) : (
            <>
              {rows.map((row) => {
                const active = keyOf(row) === selectedKey;
                return (
                  <div
                    key={keyOf(row)}
                    role="option"
                    aria-selected={active}
                    data-id={keyOf(row)}
                    onClick={() => setSelectedKey(keyOf(row))}
                    onDoubleClick={() => open(row)}
                    className={cn(
                      "flex cursor-pointer items-center gap-3 rounded-md border-l-2 px-2.5 py-2 transition-colors",
                      active ? "border-accent bg-selection" : "border-transparent hover:bg-selection/50",
                    )}
                  >
                    <span className={cn("min-w-0 flex-1 truncate text-sm", row.id === null ? "italic text-muted" : active ? "text-accent" : "text-text")}>{row.name}</span>
                    <span className="shrink-0 font-mono text-xs text-dim">{row.count}</span>
                  </div>
                );
              })}
              {groupCount === 0 && !query ? (
                <p className="px-3 py-4 text-center text-xs text-dim">No groups yet — press <Kbd>n</Kbd> to create one.</p>
              ) : null}
            </>
          )}
        </div>
      </Panel>

      <div className="hidden min-h-0 md:flex">
        {selected ? (
          <Panel
            className="flex-1"
            focused
            title={<span className={cn("text-sm normal-case tracking-normal", selected.id === null ? "italic text-muted" : "text-text")}>{selected.name}</span>}
            actions={
              <>
                <Tooltip content="Show secrets (enter)"><Button variant="ghost" size="icon-sm" onClick={() => open(selected)} aria-label="Show secrets"><FolderOpen /></Button></Tooltip>
                {selected.id !== null ? (
                  <>
                    <Tooltip content="Add secrets (a)"><Button variant="ghost" size="icon-sm" onClick={() => edit("add")} aria-label="Add secrets"><FolderPlus /></Button></Tooltip>
                    <Tooltip content="Rename (e)"><Button variant="ghost" size="icon-sm" onClick={() => edit("rename")} aria-label="Rename"><Pencil /></Button></Tooltip>
                    <Tooltip content="Delete (x)"><Button variant="ghost" size="icon-sm" onClick={() => edit("delete")} aria-label="Delete" className="hover:text-danger"><Trash2 /></Button></Tooltip>
                  </>
                ) : null}
              </>
            }
            bodyClassName="overflow-y-auto"
          >
            <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-1.5 border-b border-border px-4 py-3.5 text-sm">
              <dt className="text-dim">Secrets</dt><dd className="text-text">{selected.count}</dd>
              {selected.createdAt ? (
                <><dt className="text-dim">Created</dt><dd className="text-muted">{formatDate(selected.createdAt)}</dd></>
              ) : (
                <><dt className="text-dim">About</dt><dd className="text-muted">Secrets not in any group</dd></>
              )}
            </dl>
            {members.length === 0 ? (
              <Empty icon={<Folders />} title="No secrets here yet">{selected.id === null ? "Every secret is in a group." : <>Press <Kbd>a</Kbd> to add secrets, or pick this group when you edit a secret.</>}</Empty>
            ) : (
              <ul className="p-1.5">
                {members.map((secret) => {
                  const meta = TYPE_META[secret.type];
                  return (
                    <li key={secret.id} className="flex items-center gap-3 rounded-md px-2.5 py-1.5 text-sm">
                      <span className={cn("w-3 shrink-0 text-center text-xs", meta.color)} aria-hidden>{meta.glyph}</span>
                      <span className="truncate text-text">{secret.name}</span>
                    </li>
                  );
                })}
              </ul>
            )}
          </Panel>
        ) : (
          <Panel className="flex-1">
            <Empty icon={<Folders />} title="Nothing selected">Pick a group on the left, or press <Kbd>n</Kbd> to create one.</Empty>
          </Panel>
        )}
      </div>

      <Dialog open={dialog?.kind === "new" || dialog?.kind === "rename"} onOpenChange={(isOpen) => !isOpen && setDialog(null)}>
        {dialog?.kind === "new" || dialog?.kind === "rename" ? (
          <NameDialog
            title={dialog.kind === "new" ? "New group" : `Rename ${dialog.row.name}`}
            initial={dialog.kind === "rename" ? dialog.row.name : ""}
            action={dialog.kind === "new" ? "Create" : "Rename"}
            onSave={async (name) => {
              const saved = dialog.kind === "new" ? await api.createGroup(name) : await api.renameGroup(dialog.row.id!, name);
              toast.success(dialog.kind === "new" ? `Created group "${saved.name}"` : `Renamed to "${saved.name}"`);
              setDialog(null);
              setSelectedKey(saved.id);
              await load();
            }}
          />
        ) : null}
      </Dialog>

      <Dialog open={dialog?.kind === "add"} onOpenChange={(isOpen) => !isOpen && setDialog(null)}>
        {dialog?.kind === "add" ? (
          <AddSecretsDialog group={{ id: dialog.row.id!, name: dialog.row.name }} secrets={secrets} onChanged={() => void load()} />
        ) : null}
      </Dialog>

      <Dialog open={dialog?.kind === "delete"} onOpenChange={(isOpen) => !isOpen && setDialog(null)}>
        {dialog?.kind === "delete" ? (
          <ConfirmDialog
            title={`Delete group "${dialog.row.name}"?`}
            body={`${dialog.row.count} secret${dialog.row.count === 1 ? "" : "s"} become${dialog.row.count === 1 ? "s" : ""} ungrouped, none deleted.`}
            action="Delete group"
            onConfirm={() => remove(dialog.row)}
            onCancel={() => setDialog(null)}
          />
        ) : null}
      </Dialog>
    </div>
  );
}

/** One-field name prompt for create and rename; the server's error shows under the field. */
function NameDialog({ title, initial, action, onSave }: { title: string; initial: string; action: string; onSave: (name: string) => Promise<void> }) {
  const [name, setName] = useState(initial);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!name.trim()) return setError("Group name is required");
    setBusy(true);
    try {
      await onSave(name);
    } catch (e) {
      setError(errorMessage(e));
      setBusy(false);
    }
  };

  return (
    <DialogContent title={title}>
      <form onSubmit={(e) => void submit(e)}>
        <Field label="Name" htmlFor="group-name" error={error || undefined}>
          <Input id="group-name" autoFocus value={name} onChange={(e) => { setName(e.target.value); setError(""); }} placeholder="e.g. homelab" maxLength={64} aria-invalid={Boolean(error) || undefined} />
        </Field>
        <DialogFooter>
          <Button type="submit" variant="primary" disabled={busy}>
            {busy ? <Spinner className="border-on-accent/30 border-t-on-accent" /> : null}{action}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}

/** a: add secrets to a group or take them out, the same as the link dialog. A secret in another group moves. */
function AddSecretsDialog({ group, secrets, onChanged }: { group: { id: string; name: string }; secrets: SecretEntry[]; onChanged: () => void }) {
  const [query, setQuery] = useState("");
  const [groupOf, setGroupOf] = useState(() => new Map(secrets.map((s) => [s.id, { id: s.groupId, name: s.group }])));
  const [busy, setBusy] = useState<string | null>(null);
  const [cursor, setCursor] = useState(0);

  const candidates = useMemo(() => fuzzyFilter(secrets, query, (s) => [s.name, s.username, s.url]), [secrets, query]);

  useEffect(() => setCursor(0), [query]);

  const toggle = async (target: SecretEntry) => {
    if (busy) return;
    setBusy(target.id);
    const current = groupOf.get(target.id);
    const member = current?.id === group.id;
    try {
      await api.updateSecret(target.id, { group: member ? null : group.id });
      setGroupOf((map) => new Map(map).set(target.id, member ? { id: null, name: null } : { id: group.id, name: group.name }));
      if (member) toast.success(`Removed ${target.name} from ${group.name}`);
      else toast.success(current?.name ? `Moved ${target.name} from ${current.name} to ${group.name}` : `Added ${target.name} to ${group.name}`);
      onChanged();
    } catch (error) {
      toast.error(errorMessage(error));
    } finally {
      setBusy(null);
    }
  };

  return (
    <DialogContent title={`Add secrets · ${group.name}`} description="A secret is in one group at a time; adding one from another group moves it here." className="w-[min(92vw,34rem)]">
      <Input
        autoFocus
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        placeholder="Search secrets"
        aria-label="Search secrets to add"
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
          <p className="px-3 py-6 text-center text-sm text-dim">No secrets{query ? " match" : ""}.</p>
        ) : (
          candidates.map((candidate, index) => {
            const current = groupOf.get(candidate.id);
            const member = current?.id === group.id;
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
                ) : member ? (
                  <span className="flex items-center gap-1 text-xs text-success"><Check className="size-3.5" />added</span>
                ) : (
                  <span className="truncate text-xs text-dim">{current?.name ? `move from ${current.name}` : "add"}</span>
                )}
              </button>
            );
          })
        )}
      </div>
      <p className="mt-2 text-xs text-dim"><Kbd>↑↓</Kbd> move · <Kbd>enter</Kbd> add / remove · <Kbd>esc</Kbd> done</p>
    </DialogContent>
  );
}
