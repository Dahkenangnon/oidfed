import { defineProject } from "vitest/config";

export default defineProject({
	test: {
		globals: true,
		environment: "node",
		coverage: {
			thresholds: {
				statements: 85,
				branches: 75,
				functions: 85,
				lines: 85,
			},
		},
	},
});
