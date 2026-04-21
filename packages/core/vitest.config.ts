import { defineProject } from "vitest/config";

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
});
