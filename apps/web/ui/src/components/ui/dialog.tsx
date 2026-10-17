import { Dialog as DialogPrimitive } from "radix-ui";
import { X } from "lucide-react";
import type { ComponentProps, ReactNode } from "react";

import { cn } from "../../lib/utils.ts";

export const Dialog = DialogPrimitive.Root;
export const DialogClose = DialogPrimitive.Close;

export function DialogContent({ className, children, title, description, danger, hideClose, ...props }: Omit<ComponentProps<typeof DialogPrimitive.Content>, "title"> & {
  title: ReactNode;
  description?: ReactNode;
  danger?: boolean;
  hideClose?: boolean;
}) {
  return (
    <DialogPrimitive.Portal>
      <DialogPrimitive.Overlay className="fixed inset-0 z-50 bg-black/70 backdrop-blur-[2px] animate-in" />
      <DialogPrimitive.Content
        className={cn(
          "fixed left-1/2 top-[10vh] z-50 flex max-h-[80vh] w-[min(92vw,30rem)] -translate-x-1/2 flex-col overflow-hidden rounded-xl border bg-panel shadow-2xl shadow-black/60 animate-in focus:outline-none",
          danger ? "border-danger/60" : "border-border-focus",
          className,
        )}
        {...props}
      >
        <div className="flex items-start justify-between gap-4 border-b border-border px-5 py-3.5">
          <div className="min-w-0">
            <DialogPrimitive.Title className={cn("text-sm font-semibold", danger ? "text-danger" : "text-accent")}>{title}</DialogPrimitive.Title>
            {description ? (
              <DialogPrimitive.Description className="mt-1 text-xs text-muted">{description}</DialogPrimitive.Description>
            ) : (
              <DialogPrimitive.Description className="sr-only">{typeof title === "string" ? title : "Dialog"}</DialogPrimitive.Description>
            )}
          </div>
          {hideClose ? null : (
            <DialogPrimitive.Close className="cursor-pointer rounded p-1 text-dim hover:bg-selection hover:text-text" aria-label="Close">
              <X className="size-4" />
            </DialogPrimitive.Close>
          )}
        </div>
        <div className="overflow-y-auto px-5 py-4">{children}</div>
      </DialogPrimitive.Content>
    </DialogPrimitive.Portal>
  );
}

export function DialogFooter({ className, ...props }: ComponentProps<"div">) {
  return <div className={cn("mt-5 flex flex-wrap items-center justify-end gap-2", className)} {...props} />;
}
