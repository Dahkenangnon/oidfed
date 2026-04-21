import { generateSigningKey, signEntityStatement } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { handler } from "../../src/commands/decode.js";
import { JsonFormatter } from "../../src/output/json.js";
import { createLogger } from "../../src/util/logger.js";

const deps = {
	formatter: new JsonFormatter(),
	logger: createLogger({ quiet: true, verbose: false }),
};

async function makeJwt() {
	const key = await generateSigningKey("ES256");
	return signEntityStatement(
		{ iss: "https://ta.example.com", sub: "https://ta.example.com", iat: 1000, exp: 9999999999 },
		key.privateKey,
	);
}

describe("decode handler", () => {
	it("decodes JWT payload", async () => {
		const jwt = await makeJwt();
		const result = handler({ jwt, headerOnly: false }, deps);
		expect(result.ok).toBe(true);
		if (result.ok) {
			const parsed = JSON.parse(result.value);
			expect(parsed.iss).toBe("https://ta.example.com");
		}
	});

	it("decodes JWT header only", async () => {
		const jwt = await makeJwt();
		const result = handler({ jwt, headerOnly: true }, deps);
		expect(result.ok).toBe(true);
		if (result.ok) {
			const parsed = JSON.parse(result.value);
			expect(parsed.alg).toBe("ES256");
			expect(parsed.typ).toBe("entity-statement+jwt");
		}
	});

	it("returns error for invalid JWT", () => {
		const result = handler({ jwt: "not-a-jwt", headerOnly: false }, deps);
		expect(result.ok).toBe(false);
	});
});
