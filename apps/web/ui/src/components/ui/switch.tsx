import { Switch as SwitchPrimitive } from "radix-ui";
import type { ComponentProps } from "react";

import { cn } from "../../lib/utils.ts";

export function Switch({ className, ...props }: ComponentProps<typeof SwitchPrimitive.Root>) {
  return (
    <SwitchPrimitive.Root
      className={cn(
        "relative inline-flex h-5 w-9 shrink-0 cursor-pointer items-center rounded-full border border-border bg-chip transition-colors data-[state=checked]:border-accent data-[state=checked]:bg-accent/25 disabled:cursor-not-allowed disabled:opacity-40",
        className,
      )}
      {...props}
    >
      <SwitchPrimitive.Thumb className="block size-3.5 translate-x-0.5 rounded-full bg-muted transition-transform data-[state=checked]:translate-x-[18px] data-[state=checked]:bg-accent" />
    </SwitchPrimitive.Root>
  );
}
