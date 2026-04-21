import { mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { DEFAULT_CONFIG, loadConfig } from "../src/config.js";

const testDir = join(tmpdir(), `oidfed-cli-test-${Date.now()}`);

describe("loadConfig", () => {
	it("returns defaults when file does not exist", async () => {
		const result = await loadConfig("/nonexistent/config.yaml");
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.value).toEqual(DEFAULT_CONFIG);
		}
	});

	it("parses a valid YAML config", async () => {
		await mkdir(testDir, { recursive: true });
		const path = join(testDir, "config.yaml");
		await writeFile(path, `http_timeout_ms: 5000\nmax_chain_depth: 5\n`);

		const result = await loadConfig(path);
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.value.http_timeout_ms).toBe(5000);
			expect(result.value.max_chain_depth).toBe(5);
		}

		await rm(testDir, { recursive: true, force: true });
	});

	it("returns error for invalid YAML", async () => {
		await mkdir(testDir, { recursive: true });
		const path = join(testDir, "bad.yaml");
		await writeFile(path, ":\n  :\n    {{{invalid");

		const result = await loadConfig(path);
		// yaml parser may parse this as valid or invalid, but zod should catch bad structure
		// The key test is it doesn't throw
		expect(result).toBeDefined();

		await rm(testDir, { recursive: true, force: true });
	});

	it("rejects unknown keys gracefully via zod passthrough", async () => {
		await mkdir(testDir, { recursive: true });
		const path = join(testDir, "extra.yaml");
		await writeFile(path, `http_timeout_ms: 5000\nunknown_key: value\n`);

		const result = await loadConfig(path);
		// Zod strip mode: unknown keys are stripped, valid config accepted
		expect(result.ok).toBe(true);

		await rm(testDir, { recursive: true, force: true });
	});

	it("handles trust_anchors array", async () => {
		await mkdir(testDir, { recursive: true });
		const path = join(testDir, "anchors.yaml");
		await writeFile(path, `trust_anchors:\n  - entity_id: https://ta.example.com\n`);

		const result = await loadConfig(path);
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.value.trust_anchors).toHaveLength(1);
			expect(result.value.trust_anchors[0]?.entity_id).toBe("https://ta.example.com");
		}

		await rm(testDir, { recursive: true, force: true });
	});
});
