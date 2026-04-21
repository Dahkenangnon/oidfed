import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const __dirname = dirname(fileURLToPath(import.meta.url));
const packages = resolve(__dirname, "../../packages");

export default defineConfig({
	test: {
		name: "e2e",
		setupFiles: [resolve(__dirname, "helpers/setup-file.ts")],
		include: [resolve(__dirname, "scenarios/**/*.test.ts")],
		testTimeout: 30_000,
		hookTimeout: 30_000,
		sequence: {
			concurrent: false,
		},
	},
	resolve: {
		alias: {
			"@oidfed/core": resolve(packages, "core/src/index.ts"),
			"@oidfed/authority": resolve(packages, "authority/src/index.ts"),
			"@oidfed/leaf": resolve(packages, "leaf/src/index.ts"),
			"@oidfed/oidc": resolve(packages, "oidc/src/index.ts"),
		},
	},
});
