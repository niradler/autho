import type { ReactNode } from "react";

import { testRender } from "@opentui/react/test-utils";

// Never touch the developer's real keychain from tests.
process.env.AUTHO_DISABLE_OS_SECRETS = "1";

/**
 * testRender turns on React's act() environment, but OpenTUI drives updates
 * from its own input events, so every keypress would log an act() warning.
 */
export async function render(node: ReactNode, options: Parameters<typeof testRender>[1]) {
  const harness = await testRender(node, options);
  (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = false;
  return harness;
}
