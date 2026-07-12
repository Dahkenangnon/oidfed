import { entityId } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { getOidcClientEntity } from "../helpers/launcher.js";
import { useFederation } from "../helpers/lifecycle.js";
import { singleAnchorTopology } from "../topologies/single-anchor.js";

describe("JTI replay detection", () => {
	const getTestBed = useFederation(singleAnchorTopology);

	it("rejects replayed Request Object JWT (same JTI)", async () => {
		const { server, entities, trustAnchors } = getTestBed();
		const port = server.port;

		const rpEntity = getOidcClientEntity(entities, "https://rp.ofed.test");

		const rpId = `https://rp.ofed.test:${port}`;
		const opId = entityId(`https://op.ofed.test:${port}`);

		const resultVal = await rpEntity.oidcClient.automaticallyRegister(
			{
				opEntityId: opId,
				redirect_uri: `${rpId}/callback`,
				scope: "openid",
				requestDelivery: "query",
			},
			{ trustAnchors },
		);

		expect(resultVal.ok).toBe(true);
		if (!resultVal.ok) throw new Error("Registration failed");
		const result = resultVal.value;

		expect(result.delivery).toBe("query");
		if (result.delivery !== "query") return;

		// First request — should succeed (< 500)
		const firstResponse = await fetch(result.authorizationUrl);
		expect(firstResponse.status).toBeLessThan(500);

		// Second request with same JWT — should fail due to JTI replay
		const secondResponse = await fetch(result.authorizationUrl);
		expect(secondResponse.status).toBe(400);

		const body = (await secondResponse.json()) as { error: string };
		expect(body.error).toBeDefined();
	});
});
