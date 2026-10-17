import { Label as LabelPrimitive } from "radix-ui";
import type { ComponentProps, ReactNode } from "react";

import { cn } from "../../lib/utils.ts";

const fieldBase =
  "w-full rounded-md border border-border bg-input px-3 text-sm text-text placeholder:text-dim transition-colors focus:border-accent focus:bg-input-focus focus:outline-none disabled:opacity-50 aria-invalid:border-danger";

export function Input({ className, ...props }: ComponentProps<"input">) {
  return <input spellCheck={false} autoComplete="off" className={cn(fieldBase, "h-9", className)} {...props} />;
}

export function Textarea({ className, ...props }: ComponentProps<"textarea">) {
  return <textarea spellCheck={false} className={cn(fieldBase, "min-h-24 resize-y py-2 leading-relaxed", className)} {...props} />;
}

export function Label({ className, ...props }: ComponentProps<typeof LabelPrimitive.Root>) {
  return <LabelPrimitive.Root className={cn("text-xs font-medium uppercase tracking-wide text-muted", className)} {...props} />;
}

/** Label, control and an optional hint or error, stacked. */
export function Field({ label, htmlFor, hint, error, children, className }: {
  label: ReactNode;
  htmlFor?: string;
  hint?: ReactNode;
  error?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-col gap-1.5", className)}>
      <Label htmlFor={htmlFor}>{label}</Label>
      {children}
      {error ? <p className="text-xs text-danger">{error}</p> : hint ? <p className="text-xs text-dim">{hint}</p> : null}
    </div>
  );
}
