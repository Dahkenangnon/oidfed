import { describe, expect, it } from "vitest";
import { handler } from "../../src/commands/keygen.js";
import { JsonFormatter } from "../../src/output/json.js";
import { createLogger } from "../../src/util/logger.js";

const deps = {
	formatter: new JsonFormatter(),
	logger: createLogger({ quiet: true, verbose: false }),
};

describe("keygen handler", () => {
	it("generates ES256 key pair by default", async () => {
		const result = await handler({ algorithm: "ES256", publicOnly: false }, deps);
		expect(result.ok).toBe(true);
		if (result.ok) {
			const parsed = JSON.parse(result.value);
			expect(parsed.publicKey.alg).toBe("ES256");
			expect(parsed.publicKey.use).toBe("sig");
			expect(parsed.privateKey.alg).toBe("ES256");
			expect(parsed.publicKey.kid).toBeDefined();
		}
	});

	it("outputs public key only as JWKS", async () => {
		const result = await handler({ algorithm: "ES256", publicOnly: true }, deps);
		expect(result.ok).toBe(true);
		if (result.ok) {
			const parsed = JSON.parse(result.value);
			expect(parsed.keys).toHaveLength(1);
			expect(parsed.keys[0].d).toBeUndefined();
		}
	});

	it("supports PS256", async () => {
		const result = await handler({ algorithm: "PS256", publicOnly: false }, deps);
		expect(result.ok).toBe(true);
		if (result.ok) {
			const parsed = JSON.parse(result.value);
			expect(parsed.publicKey.alg).toBe("PS256");
		}
	});

	it("rejects unsupported algorithm", async () => {
		const result = await handler({ algorithm: "HMAC", publicOnly: false }, deps);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.description).toContain("Unsupported algorithm");
		}
	});
});
