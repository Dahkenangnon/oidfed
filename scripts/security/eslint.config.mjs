/** Type-aware checks that complement Biome's formatting and recommended rules. */

import tseslint from "typescript-eslint";
import regexp from "eslint-plugin-regexp";
import jsdoc from "eslint-plugin-jsdoc";
import protocol from "./eslint-rules.mjs";
import { root, sources } from "./scope.mjs";

export default [
	{
		files: sources.map((source) => `${source}/**/*.{ts,tsx,js,jsx,mjs,cjs}`),
		languageOptions: { parser: tseslint.parser },
		plugins: { protocol },
		rules: {
			"no-eval": "error",
			"no-new-func": "error",
			"protocol/no-wrapped-function-constructor": "error",
			"protocol/no-inherited-auth-dispatch": "error",
			"protocol/no-prototype-assign-from-json": "error",
			"protocol/no-unbounded-fetch": "error",
			"protocol/no-secret-logging": "error",
		},
	},
	{
		files: sources.map((source) => `${source}/**/*.ts`),
		languageOptions: {
			parser: tseslint.parser,
			parserOptions: { projectService: true, tsconfigRootDir: root },
		},
		plugins: { "@typescript-eslint": tseslint.plugin, regexp, jsdoc },
		rules: {
			"@typescript-eslint/no-unsafe-assignment": "error",
			"@typescript-eslint/no-unsafe-argument": "error",
			"@typescript-eslint/no-unsafe-member-access": "error",
			"@typescript-eslint/no-unsafe-call": "error",
			"@typescript-eslint/no-unsafe-return": "error",
			"@typescript-eslint/await-thenable": "error",
			"@typescript-eslint/no-floating-promises": "error",
			"@typescript-eslint/no-misused-promises": "error",
			"@typescript-eslint/switch-exhaustiveness-check": "error",
			"regexp/no-super-linear-backtracking": "error",
			"regexp/no-super-linear-move": "error",
			"jsdoc/check-param-names": "error",
			"jsdoc/check-tag-names": ["error", { definedTags: ["defaultValue"] }],
		},
	},
];
