import { defineProject } from "vitest/config";
import path from "node:path";

export default defineProject({
	test: {
		globals: true,
		environment: "node",
		coverage: {
			thresholds: {
				statements: 90,
				branches: 85,
				functions: 90,
				lines: 90,
			},
		},
	},
	resolve: {
		alias: {
			"@oidfed/core": path.resolve(__dirname, "../core/src/index.ts"),
		},
	},
});
