import type { ComponentProps, ReactNode } from "react";

import { cn } from "../../lib/utils.ts";

/** A rounded, titled box: the TUI's bordered panels. */
export function Panel({ title, actions, className, bodyClassName, children, focused, ...props }: Omit<ComponentProps<"section">, "title"> & {
  title?: ReactNode;
  actions?: ReactNode;
  bodyClassName?: string;
  focused?: boolean;
}) {
  return (
    <section className={cn("flex min-h-0 flex-col rounded-xl border bg-panel", focused ? "border-border-focus" : "border-border", className)} {...props}>
      {title || actions ? (
        <header className="flex min-h-11 items-center justify-between gap-3 border-b border-border px-4 py-2">
          <h2 className="truncate text-xs font-semibold uppercase tracking-wider text-muted">{title}</h2>
          {actions ? <div className="flex items-center gap-1.5">{actions}</div> : null}
        </header>
      ) : null}
      <div className={cn("min-h-0 flex-1", bodyClassName)}>{children}</div>
    </section>
  );
}

export function Kbd({ children, className }: { children: ReactNode; className?: string }) {
  return <kbd className={cn("kbd", className)}>{children}</kbd>;
}

export function Empty({ icon, title, children }: { icon?: ReactNode; title: ReactNode; children?: ReactNode }) {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-2 px-6 py-12 text-center">
      {icon ? <div className="text-dim [&_svg]:size-8">{icon}</div> : null}
      <p className="text-sm font-medium text-muted">{title}</p>
      {children ? <div className="max-w-sm text-xs text-dim">{children}</div> : null}
    </div>
  );
}

export function Spinner({ className }: { className?: string }) {
  return <span className={cn("inline-block size-4 animate-spin rounded-full border-2 border-dim border-t-accent", className)} aria-label="Loading" />;
}
