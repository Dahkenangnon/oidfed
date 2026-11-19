import { defineConfig } from "tsup";

export default defineConfig({
	entry: ["src/index.ts", "src/web.ts", "src/jose.ts"],
	format: ["esm", "cjs"],
	dts: true,
	clean: true,
	sourcemap: true,
	splitting: false,
	// Preserve root error identity and optional-backend isolation across entrypoints.
	external: ["@oidfed/crypto", "@oidfed/crypto/web", "jose"],
	outDir: "dist",
});
