import { Command as CommandIcon, Lock } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { Button } from "./components/ui/button.tsx";
import { Kbd } from "./components/ui/panel.tsx";
import { Tooltip } from "./components/ui/tooltip.tsx";
import { useApp, type Command, type Screen } from "./context.tsx";
import { UNGROUPED_LABEL, api, type Group } from "./lib/api.ts";
import { cn, isMac, isTypingTarget } from "./lib/utils.ts";
import { Palette } from "./palette.tsx";
import { AuditScreen } from "./screens/audit.tsx";
import { GroupsScreen } from "./screens/groups.tsx";
import { HealthScreen } from "./screens/health.tsx";
import { LeasesScreen } from "./screens/leases.tsx";
import { SettingsScreen } from "./screens/settings.tsx";
import { Logo } from "./screens/unlock.tsx";
import { VaultScreen } from "./screens/vault.tsx";

const NAV: { screen: Screen; label: string; key: string }[] = [
  { screen: "vault", label: "Vault", key: "1" },
  { screen: "groups", label: "Groups", key: "2" },
  { screen: "leases", label: "Leases", key: "3" },
  { screen: "audit", label: "Audit", key: "4" },
  { screen: "health", label: "Integrity", key: "5" },
  { screen: "settings", label: "Settings", key: "," },
];

export function Shell() {
  const app = useApp();
  const mod = isMac() ? "⌘" : "ctrl";

  // Global keys, like the TUI: ctrl+k palette, ctrl+l lock; plain keys only outside fields and dialogs.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      const ctrl = event.ctrlKey || event.metaKey;
      if (ctrl && !event.shiftKey && !event.altKey && event.key.toLowerCase() === "k") {
        event.preventDefault();
        app.setPaletteOpen(!app.paletteOpen);
        return;
      }
      if (ctrl && !event.shiftKey && !event.altKey && event.key.toLowerCase() === "l") {
        event.preventDefault();
        app.lock();
        return;
      }
      if (ctrl || event.altKey || app.paletteOpen || app.modalOpen || isTypingTarget(event.target)) return;
      if (event.key === "?") {
        event.preventDefault();
        app.setPaletteOpen(true);
        return;
      }
      const nav = NAV.find((n) => n.key === event.key);
      if (nav) {
        event.preventDefault();
        app.go(nav.screen);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [app]);

  // Group rows are fetched each time the palette opens, so counts are current.
  const [groupRows, setGroupRows] = useState<{ groups: Group[]; ungrouped: number } | null>(null);
  useEffect(() => {
    if (!app.paletteOpen) return;
    let cancelled = false;
    void Promise.all([api.groups(), api.secrets()])
      .then(([groups, secrets]) => {
        if (!cancelled) setGroupRows({ groups, ungrouped: secrets.filter((s) => s.groupId === null).length });
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [app.paletteOpen]);

  const globalCommands = useMemo<Command[]>(() => [
    ...(groupRows?.groups ?? []).map((g) => ({
      id: `group:${g.id}`, title: g.name, group: "Group", hint: String(g.secretCount), keywords: "group", run: () => app.openGroup({ id: g.id, name: g.name }),
    })),
    ...(groupRows
      ? [{ id: "group:ungrouped", title: UNGROUPED_LABEL, group: "Group", hint: String(groupRows.ungrouped), keywords: "group", run: () => app.openGroup({ id: null, name: UNGROUPED_LABEL }) }]
      : []),
    ...NAV.map((n) => ({ id: `go:${n.screen}`, title: `Go to ${n.label}`, group: "Navigate", hint: n.key, run: () => app.go(n.screen) })),
    { id: "lock", title: "Lock vault", group: "App", hint: `${mod}+l`, run: () => app.lock() },
  ], [app, mod, groupRows]);

  const title = NAV.find((n) => n.screen === app.screen)?.label ?? "";

  return (
    <div className="flex h-full flex-col">
      <header className="flex h-12 shrink-0 items-center gap-4 border-b border-border bg-panel px-4">
        <div className="flex items-center gap-3">
          <Logo />
          <span className="hidden font-semibold text-text sm:inline">{title}</span>
        </div>
        <nav className="flex min-w-0 flex-1 items-center gap-0.5 overflow-x-auto" aria-label="Main">
          {NAV.map((n) => (
            <button
              key={n.screen}
              type="button"
              onClick={() => app.go(n.screen)}
              aria-current={app.screen === n.screen ? "page" : undefined}
              className={cn(
                "cursor-pointer rounded-md px-3 py-1.5 text-sm transition-colors",
                app.screen === n.screen ? "bg-selection text-accent" : "text-muted hover:bg-selection/60 hover:text-text",
              )}
            >
              {n.label}
            </button>
          ))}
        </nav>
        <div className="flex items-center gap-2">
          <Tooltip content={app.session.vault.path} side="bottom">
            <span className="hidden items-center gap-1.5 font-mono text-xs text-muted md:flex">
              <span className="text-success">●</span> unlocked <span className="text-dim">·</span> {app.session.vault.name}
            </span>
          </Tooltip>
          <Tooltip content={`Command palette (${mod}+k)`} side="bottom">
            <Button variant="ghost" size="icon" onClick={() => app.setPaletteOpen(true)} aria-label="Command palette">
              <CommandIcon />
            </Button>
          </Tooltip>
          <Tooltip content={`Lock (${mod}+l)`} side="bottom">
            <Button variant="ghost" size="icon" onClick={() => app.lock()} aria-label="Lock vault">
              <Lock />
            </Button>
          </Tooltip>
        </div>
      </header>

      <main className="min-h-0 flex-1 overflow-hidden p-3 sm:p-4">
        {app.screen === "vault" ? <VaultScreen /> : null}
        {app.screen === "groups" ? <GroupsScreen /> : null}
        {app.screen === "leases" ? <LeasesScreen /> : null}
        {app.screen === "audit" ? <AuditScreen /> : null}
        {app.screen === "health" ? <HealthScreen /> : null}
        {app.screen === "settings" ? <SettingsScreen /> : null}
      </main>

      <footer className="flex h-9 shrink-0 items-center gap-4 overflow-hidden border-t border-border bg-panel px-4 text-xs text-dim">
        {app.hints.map(([key, label]) => (
          <span key={key + label} className="flex shrink-0 items-center gap-1.5">
            <Kbd>{key}</Kbd>
            {label}
          </span>
        ))}
        <span className="ml-auto flex shrink-0 items-center gap-1.5">
          <Kbd>{mod}+k</Kbd> commands
          <Kbd className="ml-2">{mod}+l</Kbd> lock
        </span>
      </footer>

      <Palette commands={[...app.screenCommands, ...globalCommands]} />
    </div>
  );
}
