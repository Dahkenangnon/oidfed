/** Package layering and runtime portability rules for published sources. */

import { sources } from "./scope.mjs";

export default {
	forbidden: [
		{
			name: "core-is-independent",
			severity: "error",
			from: { path: "^packages/core/src" },
			to: { path: "^packages/(authority|leaf|oidc|wallet)/" },
		},
		{
			name: "no-private-cross-package-imports",
			severity: "error",
			from: { path: "^packages/([^/]+)/src" },
			to: {
				path: "^packages/([^/]+)/src",
				pathNot: ["^packages/$1/", "^packages/(core|authority|leaf|oidc|wallet)/src/index\\.ts$"],
			},
		},
		{
			name: "web-runtime-only",
			severity: "error",
			from: { path: "^packages/" },
			to: { dependencyTypes: ["core"] },
		},
		{
			name: "no-application-or-tool-imports",
			severity: "error",
			from: { path: "^packages/" },
			to: { path: "^(apps|tools)/" },
		},
		{ name: "no-new-cycles", severity: "error", from: {}, to: { circular: true } },
	],
	options: {
		// Keep external edges for validation, without reading their implementations.
		doNotFollow: { path: `^(?!(?:${sources.join("|")})/)` },
		tsPreCompilationDeps: false,
		tsConfig: { fileName: "tests/tap/tsconfig.json" },
		enhancedResolveOptions: {
			exportsFields: ["exports"],
			conditionNames: ["import", "types", "default"],
		},
	},
};
