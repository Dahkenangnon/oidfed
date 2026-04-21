import { entityId } from "@oidfed/core";
import { discoverEntity } from "@oidfed/leaf";
import { automaticRegistration } from "@oidfed/oidc";
import { describe, expect, it } from "vitest";
import { getEntity } from "../helpers/launcher.js";
import { useFederation } from "../helpers/lifecycle.js";
import { singleAnchorTopology } from "../topologies/single-anchor.js";

describe("JTI replay detection", () => {
	const getTestBed = useFederation(singleAnchorTopology);

	it("rejects replayed Request Object JWT (same JTI)", async () => {
		const { server, entities, trustAnchors } = getTestBed();
		const port = server.port;

		const rpEntity = getEntity(entities, "https://rp.ofed.test");

		const rpId = `https://rp.ofed.test:${port}`;
		const opId = entityId(`https://op.ofed.test:${port}`);
		const discovery = await discoverEntity(opId, trustAnchors);

		const result = await automaticRegistration(
			discovery,
			{
				entityId: entityId(rpId),
				signingKeys: [rpEntity.keys.signing],
				authorityHints: [entityId(`https://ta.ofed.test:${port}`)],
				metadata: {
					openid_relying_party: {
						redirect_uris: [`${rpId}/callback`],
						response_types: ["code"],
						grant_types: ["authorization_code"],
						client_registration_types: ["automatic"],
						token_endpoint_auth_method: "private_key_jwt",
					},
				},
			},
			{
				client_id: rpId,
				redirect_uri: `${rpId}/callback`,
				response_type: "code",
				scope: "openid",
			},
			trustAnchors,
		);

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
