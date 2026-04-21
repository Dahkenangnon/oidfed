import { entityId, InternalErrorCode, resolveTrustChains, validateTrustChain } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { useFederation } from "../helpers/lifecycle.js";
import { constrainedTopology } from "../topologies/constrained.js";

describe("Constraint enforcement — maxPathLength", () => {
	const getTestBed = useFederation(constrainedTopology);

	it("direct subordinate resolves successfully (path length = 0 intermediates)", async () => {
		const { server, trustAnchors } = getTestBed();
		const port = server.port;

		const opDirectId = entityId(`https://op-direct.ofed.test:${port}`);
		const result = await resolveTrustChains(opDirectId, trustAnchors);

		expect(result.chains).toHaveLength(1);
		expect(result.errors).toHaveLength(0);

		// Validate the chain
		const validation = await validateTrustChain([...result.chains[0].statements], trustAnchors);
		expect(validation.errors).toHaveLength(0);
	});

	it("nested subordinate fails validation (path length exceeds max_path_length=0)", async () => {
		const { server, trustAnchors } = getTestBed();
		const port = server.port;

		// OP-Deep is behind IA-Deep, so chain is: OP-Deep EC → IA-Deep SS → TA SS → TA EC
		// The TA's subordinate statement about IA-Deep has max_path_length=0,
		// meaning 0 intermediates between TA and the subject are allowed.
		// IA-Deep is 1 intermediate between TA and OP-Deep — exceeding max_path_length=0.
		const opDeepId = entityId(`https://op-deep.ofed.test:${port}`);
		const result = await resolveTrustChains(opDeepId, trustAnchors);

		// Chain resolution may succeed but validation should fail due to constraint violation
		if (result.chains.length > 0) {
			const validation = await validateTrustChain([...result.chains[0].statements], trustAnchors, {
				verboseErrors: true,
			});
			expect(validation.errors.length).toBeGreaterThan(0);
			const hasConstraintError = validation.errors.some(
				(e) =>
					e.code === InternalErrorCode.ConstraintViolation || e.message.includes("max_path_length"),
			);
			expect(hasConstraintError).toBe(true);
		} else {
			// If resolution itself caught the constraint, that's also acceptable
			expect(result.errors.length).toBeGreaterThan(0);
		}
	});
});
