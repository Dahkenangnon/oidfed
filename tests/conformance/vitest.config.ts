import { tmpdir } from "node:os";
import { join } from "node:path";
import { defineConfig } from "vitest/config";

export default defineConfig({
	// The Docker runner mounts the repository read-only.
	cacheDir: join(tmpdir(), "oidfed-conformance-vitest"),
	test: {
		projects: [
			{
				test: {
					name: "unit",
					environment: "node",
					include: ["tests/conformance/harness.test.ts"],
					retry: 0,
				},
			},
			{
				test: {
					name: "plans",
					environment: "node",
					include: ["tests/conformance/plans.test.ts"],
					retry: 0,
					fileParallelism: false,
					hookTimeout: 365_000,
					sequence: { concurrent: false },
				},
			},
		],
	},
});
