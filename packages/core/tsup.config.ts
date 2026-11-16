import { defineConfig } from "tsup";

export default defineConfig({
	entry: ["src/index.ts"],
	format: ["esm", "cjs"],
	// Consumers need the symbol declarations used by the public disposal methods.
	dts: { banner: '/// <reference lib="esnext.disposable" />' },
	clean: true,
	sourcemap: true,
	splitting: false,
	outDir: "dist",
});
