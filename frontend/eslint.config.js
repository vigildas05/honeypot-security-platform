import js from "@eslint/js";
import react from "eslint-plugin-react";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";

export default [
  { ignores: ["dist/", "node_modules/"] },
  js.configs.recommended,
  {
    files: ["**/*.{js,jsx}"],
    plugins: { react, "react-hooks": reactHooks },
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: "module",
      parserOptions: { ecmaFeatures: { jsx: true } },
      globals: { ...globals.browser, ...globals.node }
    },
    settings: { react: { version: "18.3" } },
    rules: {
      ...react.configs.recommended.rules,
      "react/react-in-jsx-scope": "off",
      "react/prop-types": "off",
      "react-hooks/rules-of-hooks": "error",
      "react-hooks/exhaustive-deps": "warn",
      // XSS safety: attacker strings are rendered as text only.
      "react/no-danger": "error",
      "react/no-danger-with-children": "error",
      "react/jsx-no-script-url": "error",
      "react/jsx-no-target-blank": "error",
      "no-restricted-properties": [
        "error",
        { property: "innerHTML", message: "Render attacker data as text, never HTML." },
        { property: "outerHTML", message: "Render attacker data as text, never HTML." },
        { property: "insertAdjacentHTML", message: "Render attacker data as text, never HTML." }
      ],
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-unused-vars": ["error", { argsIgnorePattern: "^_", varsIgnorePattern: "^_" }]
    }
  }
];
