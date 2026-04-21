import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		globals: true,
		environment: "node",
		projects: ["packages/*", "tools/*", "apps/explorer"],
		coverage: {
			provider: "v8",
			reporter: ["text", "json", "html"],
		},
	},
});
