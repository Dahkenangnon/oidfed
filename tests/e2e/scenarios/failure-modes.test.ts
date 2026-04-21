import { entityId, generateSigningKey, resolveTrustChains, validateTrustChain } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { launchFederation } from "../helpers/launcher.js";
import { useFederation } from "../helpers/lifecycle.js";
import { hierarchicalTopology } from "../topologies/hierarchical.js";
import { singleAnchorTopology } from "../topologies/single-anchor.js";

describe("Failure modes", () => {
	describe("single-anchor", () => {
		const getTestBed = useFederation(singleAnchorTopology);

		it("returns 404 for non-existent entity", async () => {
			const { server } = getTestBed();
			const response = await fetch(
				`https://nonexistent.ofed.test:${server.port}/.well-known/openid-federation`,
			);
			expect(response.status).toBe(404);
		});

		it("fails to resolve trust chain for unknown entity", async () => {
			const { server, trustAnchors } = getTestBed();
			const unknownId = entityId(`https://unknown.ofed.test:${server.port}`);

			const result = await resolveTrustChains(unknownId, trustAnchors);
			expect(result.chains).toHaveLength(0);
			expect(result.errors.length).toBeGreaterThan(0);
		});

		it("fails to resolve with empty trust anchor set", async () => {
			const { server } = getTestBed();
			const rpId = entityId(`https://rp.ofed.test:${server.port}`);
			const emptyAnchors = new Map();

			const result = await resolveTrustChains(rpId, emptyAnchors);
			expect(result.chains).toHaveLength(0);
		});

		it("validateTrustChain fails with wrong trust anchor keys", async () => {
			const { server, trustAnchors } = getTestBed();
			const rpId = entityId(`https://rp.ofed.test:${server.port}`);

			// First resolve chains with real anchors
			const result = await resolveTrustChains(rpId, trustAnchors);
			expect(result.chains).toHaveLength(1);

			const chain = result.chains[0];

			// Now validate the chain against fake anchors
			const fakeKey = await generateSigningKey("ES256");
			const fakeAnchors = new Map([
				[entityId(`https://ta.ofed.test:${server.port}`), { jwks: { keys: [fakeKey.publicKey] } }],
			]);

			const validation = await validateTrustChain([...chain.statements], fakeAnchors);
			expect(validation.valid).toBe(false);
			expect(validation.errors.length).toBeGreaterThan(0);
		});

		it("validateTrustChain rejects tampered entity configuration", async () => {
			const { server, trustAnchors } = getTestBed();
			const rpId = entityId(`https://rp.ofed.test:${server.port}`);

			// Resolve real chain
			const result = await resolveTrustChains(rpId, trustAnchors);
			expect(result.chains).toHaveLength(1);

			const chain = result.chains[0];
			const statements = [...chain.statements];

			// Tamper with the leaf EC (index 0)
			const parts = statements[0]?.split(".");
			const payload = JSON.parse(Buffer.from(parts[1] as string, "base64url").toString());
			payload.iss = "https://evil.example.com";
			parts[1] = Buffer.from(JSON.stringify(payload)).toString("base64url");
			statements[0] = parts.join(".");

			const validation = await validateTrustChain(statements, trustAnchors);
			expect(validation.valid).toBe(false);
		});
	});

	describe("hierarchical", () => {
		const getTestBed = useFederation(hierarchicalTopology);

		it("fails to resolve chain with mismatched trust anchor", async () => {
			const { server } = getTestBed();

			const fakeKey = await generateSigningKey("ES256");
			const wrongAnchors = new Map([
				[entityId("https://fake-ta.ofed.test:9999"), { jwks: { keys: [fakeKey.publicKey] } }],
			]);

			const opId = entityId(`https://op-uni.ofed.test:${server.port}`);
			const result = await resolveTrustChains(opId, wrongAnchors);
			expect(result.chains).toHaveLength(0);
		});
	});

	describe("expired entity configuration", () => {
		const getTestBed = useFederation(singleAnchorTopology);

		it("validateTrustChain rejects chain when clock is past expiration", async () => {
			const { server, trustAnchors } = getTestBed();
			const rpId = entityId(`https://rp.ofed.test:${server.port}`);

			// Resolve a valid chain
			const result = await resolveTrustChains(rpId, trustAnchors);
			expect(result.chains).toHaveLength(1);

			const chain = result.chains[0];

			// Validate with a clock far in the future (2 years from now)
			const futureClock = { now: () => Math.floor(Date.now() / 1000) + 2 * 365 * 86400 };
			const validation = await validateTrustChain([...chain.statements], trustAnchors, {
				clock: futureClock,
				verboseErrors: true,
			});
			expect(validation.valid).toBe(false);
			expect(validation.errors.some((e) => e.code === "ERR_EXPIRED")).toBe(true);
		});
	});

	describe("entity server unreachable", () => {
		it("fails to resolve chain when server is down", async () => {
			const testBed = await launchFederation(singleAnchorTopology);
			const port = testBed.server.port;
			const trustAnchors = testBed.trustAnchors;

			// Shut down the server
			await testBed.close();

			const rpId = entityId(`https://rp.ofed.test:${port}`);
			const result = await resolveTrustChains(rpId, trustAnchors);
			expect(result.chains).toHaveLength(0);
			expect(result.errors.length).toBeGreaterThan(0);
		});
	});
});
