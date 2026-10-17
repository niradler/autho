import { Command as Cmdk } from "cmdk";
import { Dialog as DialogPrimitive } from "radix-ui";
import { useMemo, useState } from "react";

import { useApp, type Command } from "./context.tsx";
import { fuzzyScore } from "./lib/utils.ts";

/** ctrl+k: every action on the current screen plus navigation, fuzzy-matched like the TUI palette. */
export function Palette({ commands }: { commands: Command[] }) {
  const { paletteOpen, setPaletteOpen } = useApp();
  const [query, setQuery] = useState("");

  const groups = useMemo(() => {
    const byGroup = new Map<string, Command[]>();
    for (const command of commands) {
      const list = byGroup.get(command.group) ?? [];
      list.push(command);
      byGroup.set(command.group, list);
    }
    return [...byGroup.entries()];
  }, [commands]);

  const run = (command: Command) => {
    setPaletteOpen(false);
    setQuery("");
    // Let the dialog close (and return focus) before the command opens its own.
    window.setTimeout(command.run, 0);
  };

  return (
    <DialogPrimitive.Root open={paletteOpen} onOpenChange={(open) => { setPaletteOpen(open); if (!open) setQuery(""); }}>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay className="fixed inset-0 z-50 bg-black/60 animate-in" />
        <DialogPrimitive.Content
          aria-describedby={undefined}
          className="fixed left-1/2 top-[14vh] z-50 w-[min(92vw,36rem)] -translate-x-1/2 overflow-hidden rounded-xl border border-border-focus bg-panel shadow-2xl shadow-black/70 animate-in"
        >
          <DialogPrimitive.Title className="sr-only">Command palette</DialogPrimitive.Title>
          <Cmdk
            loop
            filter={(value, search, keywords) => {
              const score = fuzzyScore(search, [value, ...(keywords ?? [])].join(" "));
              return score === null ? 0 : Math.max(0.01, Math.min(1, score / 1000));
            }}
          >
            <div className="flex items-center gap-2 border-b border-border px-4">
              <span className="font-mono text-accent">›</span>
              <Cmdk.Input
                value={query}
                onValueChange={setQuery}
                placeholder="Type a command or secret name…"
                className="h-12 flex-1 bg-transparent text-sm text-text placeholder:text-dim focus:outline-none"
              />
            </div>
            <Cmdk.List className="max-h-[50vh] overflow-y-auto p-1.5">
              <Cmdk.Empty className="px-3 py-8 text-center text-sm text-dim">No matches</Cmdk.Empty>
              {groups.map(([group, items]) => (
                <Cmdk.Group
                  key={group}
                  heading={group}
                  className="[&_[cmdk-group-heading]]:px-2.5 [&_[cmdk-group-heading]]:pb-1 [&_[cmdk-group-heading]]:pt-2.5 [&_[cmdk-group-heading]]:text-[11px] [&_[cmdk-group-heading]]:font-semibold [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-wider [&_[cmdk-group-heading]]:text-dim"
                >
                  {items.map((command) => (
                    <Cmdk.Item
                      key={command.id}
                      value={`${command.title} ${command.id}`}
                      keywords={[command.group, command.keywords ?? ""]}
                      onSelect={() => run(command)}
                      className="group flex cursor-pointer items-center justify-between gap-3 rounded-md px-2.5 py-2 text-sm text-text data-[selected=true]:bg-selection data-[selected=true]:text-accent"
                    >
                      <span className="truncate">{command.title}</span>
                      {command.hint ? <span className="kbd shrink-0 group-data-[selected=true]:text-accent">{command.hint}</span> : null}
                    </Cmdk.Item>
                  ))}
                </Cmdk.Group>
              ))}
            </Cmdk.List>
          </Cmdk>
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  );
}
