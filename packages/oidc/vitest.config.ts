import { defineProject } from "vitest/config";
import path from "node:path";

export default defineProject({
	test: {
		globals: true,
		environment: "node",
	},
	resolve: {
		alias: {
			"@oidfed/core": path.resolve(__dirname, "../core/src/index.ts"),
		},
	},
});
