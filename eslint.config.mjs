import globals from "globals";
import pluginJs from "@eslint/js";

export default [
  {
    ignores: ["node_modules/*", ".git/*", "dist/*", "build/*"]
  },
  {
    languageOptions: {
      globals: globals.node,
    }
  },
  pluginJs.configs.recommended,
];
