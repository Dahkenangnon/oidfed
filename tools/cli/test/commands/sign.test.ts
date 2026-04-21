import { decodeEntityStatement, generateSigningKey } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { handler } from "../../src/commands/sign.js";
import { JsonFormatter } from "../../src/output/json.js";
import { createLogger } from "../../src/util/logger.js";

const deps = {
	formatter: new JsonFormatter(),
	logger: createLogger({ quiet: true, verbose: false }),
	readFile: async (_path: string) => "",
};

describe("sign handler", () => {
	it("signs a payload with a private key", async () => {
		const key = await generateSigningKey("ES256");
		const payload = {
			iss: "https://example.com",
			sub: "https://example.com",
			iat: 1000,
			exp: 9999999999,
		};

		const d = {
			...deps,
			readFile: async (path: string) => {
				if (path === "payload.json") return JSON.stringify(payload);
				if (path === "key.json") return JSON.stringify(key.privateKey);
				throw new Error("not found");
			},
		};

		const result = await handler({ payloadPath: "payload.json", keyPath: "key.json" }, d);
		expect(result.ok).toBe(true);
		if (result.ok) {
			const decoded = decodeEntityStatement(result.value);
			expect(decoded.ok).toBe(true);
			if (decoded.ok) {
				expect(decoded.value.payload.iss).toBe("https://example.com");
			}
		}
	});

	it("returns error for missing payload file", async () => {
		const d = {
			...deps,
			readFile: async () => {
				throw new Error("ENOENT");
			},
		};
		const result = await handler({ payloadPath: "missing.json", keyPath: "key.json" }, d);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.description).toContain("Cannot read payload file");
		}
	});

	it("returns error for invalid JSON payload", async () => {
		const key = await generateSigningKey("ES256");
		const d = {
			...deps,
			readFile: async (path: string) => {
				if (path === "payload.json") return "not json";
				return JSON.stringify(key.privateKey);
			},
		};
		const result = await handler({ payloadPath: "payload.json", keyPath: "key.json" }, d);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.description).toContain("not valid JSON");
		}
	});

	it("returns error for missing key file", async () => {
		const d = {
			...deps,
			readFile: async (path: string) => {
				if (path === "payload.json") return "{}";
				throw new Error("ENOENT");
			},
		};
		const result = await handler({ payloadPath: "payload.json", keyPath: "key.json" }, d);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.description).toContain("Cannot read key file");
		}
	});
});
