import { defineConfig } from "tsup";

export default defineConfig([
	{
		entry: ["src/index.ts"],
		format: ["esm", "cjs"],
		dts: {
			// tsup injects deprecated baseUrl during DTS bundling.
			compilerOptions: { ignoreDeprecations: "6.0" },
		},
		clean: true,
		sourcemap: true,
		splitting: false,
		outDir: "dist",
	},
	{
		entry: ["src/bin.ts"],
		format: ["esm"],
		banner: { js: "#!/usr/bin/env node" },
		clean: false,
		sourcemap: true,
		splitting: false,
		outDir: "dist",
	},
]);
