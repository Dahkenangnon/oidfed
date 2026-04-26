import { mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { DEFAULT_CONFIG, loadConfig } from "../src/config.js";

const testDir = join(tmpdir(), `oidfed-cli-test-${Date.now()}`);

afterEach(async () => {
	await rm(testDir, { recursive: true, force: true });
	delete process.env.OIDFED_CONFIG_PATH;
});

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
	});

	it("returns error for invalid YAML", async () => {
		await mkdir(testDir, { recursive: true });
		const path = join(testDir, "bad.yaml");
		await writeFile(path, ":\n  :\n    {{{invalid");

		const result = await loadConfig(path);
		expect(result).toBeDefined();
	});

	it("rejects unknown top-level config key under .strict()", async () => {
		await mkdir(testDir, { recursive: true });
		const path = join(testDir, "extra.yaml");
		await writeFile(path, `http_timeout_ms: 5000\nunknown_key: value\n`);

		const result = await loadConfig(path);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.description).toContain("Invalid config");
		}
	});

	it("rejects max_chain_depth above 100", async () => {
		await mkdir(testDir, { recursive: true });
		const path = join(testDir, "too-deep.yaml");
		await writeFile(path, `max_chain_depth: 200\n`);

		const result = await loadConfig(path);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.description).toContain("Invalid config");
		}
	});

	it("reads OIDFED_CONFIG_PATH from environment when --config not given", async () => {
		await mkdir(testDir, { recursive: true });
		const path = join(testDir, "env.yaml");
		await writeFile(path, `http_timeout_ms: 7777\n`);
		process.env.OIDFED_CONFIG_PATH = path;

		const result = await loadConfig();
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.value.http_timeout_ms).toBe(7777);
		}
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
	});
});
