import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		globals: true,
		environment: "node",
		projects: ["tools/cli", "apps/explorer"],
		coverage: {
			provider: "v8",
			reporter: ["text", "json", "html"],
		},
	},
});
