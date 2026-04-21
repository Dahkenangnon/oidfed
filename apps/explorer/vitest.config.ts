import { resolve } from "node:path";
import { defineProject } from "vitest/config";

export default defineProject({
	test: {
		globals: true,
		environment: "jsdom",
		coverage: {
			include: ["src/lib/**", "src/hooks/**", "src/components/shared/**"],
			thresholds: {
				statements: 60,
				branches: 60,
				functions: 60,
				lines: 60,
			},
		},
	},
	resolve: {
		alias: {
			"@": resolve(__dirname, "src"),
			"@oidfed/core": resolve(__dirname, "../../packages/core/src/index.ts"),
			"@oidfed/ui": resolve(__dirname, "../../internal/ui/src/index.ts"),
		},
	},
});
