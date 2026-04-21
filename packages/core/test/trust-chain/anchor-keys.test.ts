import { describe, expect, it } from "vitest";
import { compareTrustAnchorKeys } from "../../src/trust-chain/anchor-keys.js";
import type { EntityId } from "../../src/types.js";

const entityId = "https://ta.example.com" as EntityId;

describe("compareTrustAnchorKeys", () => {
	it("returns match: true when JWK sets have same kids", () => {
		const ecJwks = {
			keys: [
				{ kty: "EC" as const, kid: "key-1", crv: "P-256", x: "x1", y: "y1" },
				{ kty: "EC" as const, kid: "key-2", crv: "P-256", x: "x2", y: "y2" },
			],
		};
		const independentJwks = {
			keys: [
				{ kty: "EC" as const, kid: "key-2", crv: "P-256", x: "x2", y: "y2" },
				{ kty: "EC" as const, kid: "key-1", crv: "P-256", x: "x1", y: "y1" },
			],
		};

		const result = compareTrustAnchorKeys(ecJwks, independentJwks, entityId);
		expect(result.match).toBe(true);
		expect(result.missingInEc).toEqual([]);
		expect(result.missingInIndependent).toEqual([]);
	});

	it("returns match: false with diff details when kids differ", () => {
		const ecJwks = {
			keys: [
				{ kty: "EC" as const, kid: "key-1", crv: "P-256", x: "x1", y: "y1" },
				{ kty: "EC" as const, kid: "key-2", crv: "P-256", x: "x2", y: "y2" },
			],
		};
		const independentJwks = {
			keys: [
				{ kty: "EC" as const, kid: "key-2", crv: "P-256", x: "x2", y: "y2" },
				{ kty: "EC" as const, kid: "key-3", crv: "P-256", x: "x3", y: "y3" },
			],
		};

		const result = compareTrustAnchorKeys(ecJwks, independentJwks, entityId);
		expect(result.match).toBe(false);
		expect(result.missingInEc).toEqual(["key-3"]);
		expect(result.missingInIndependent).toEqual(["key-1"]);
		expect(result.ecKids).toEqual(["key-1", "key-2"]);
		expect(result.independentKids).toEqual(["key-2", "key-3"]);
	});

	it("handles empty JWK sets", () => {
		const emptyJwks = {
			keys: [] as Array<{ kty: "EC"; kid: string; crv: string; x: string; y: string }>,
		};
		const nonEmptyJwks = {
			keys: [{ kty: "EC" as const, kid: "key-1", crv: "P-256", x: "x1", y: "y1" }],
		};

		const result = compareTrustAnchorKeys(emptyJwks, nonEmptyJwks, entityId);
		expect(result.match).toBe(false);
		expect(result.ecKids).toEqual([]);
		expect(result.missingInEc).toEqual(["key-1"]);
		expect(result.missingInIndependent).toEqual([]);
	});
});
