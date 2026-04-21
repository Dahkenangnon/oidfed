import type { TopologyDefinition } from "./types.js";

export const multiAnchorTopology: TopologyDefinition = {
	name: "multi-anchor",
	description: "2 TAs (gov, industry) → shared IA → OP + 2 RPs",
	entities: [
		{
			id: "https://ta-gov.ofed.test",
			role: "trust-anchor",
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: "https://ta-gov.ofed.test/federation_fetch",
					federation_list_endpoint: "https://ta-gov.ofed.test/federation_list",
					federation_resolve_endpoint: "https://ta-gov.ofed.test/federation_resolve",
					federation_historical_keys_endpoint:
						"https://ta-gov.ofed.test/federation_historical_keys",
				},
			},
		},
		{
			id: "https://ta-industry.ofed.test",
			role: "trust-anchor",
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: "https://ta-industry.ofed.test/federation_fetch",
					federation_list_endpoint: "https://ta-industry.ofed.test/federation_list",
					federation_resolve_endpoint: "https://ta-industry.ofed.test/federation_resolve",
					federation_historical_keys_endpoint:
						"https://ta-industry.ofed.test/federation_historical_keys",
				},
			},
		},
		{
			id: "https://ia-shared.ofed.test",
			role: "intermediate",
			authorityHints: ["https://ta-gov.ofed.test", "https://ta-industry.ofed.test"],
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: "https://ia-shared.ofed.test/federation_fetch",
					federation_list_endpoint: "https://ia-shared.ofed.test/federation_list",
					federation_resolve_endpoint: "https://ia-shared.ofed.test/federation_resolve",
					federation_historical_keys_endpoint:
						"https://ia-shared.ofed.test/federation_historical_keys",
				},
			},
		},
		{
			id: "https://op.ofed.test",
			role: "leaf",
			protocolRole: "op",
			authorityHints: ["https://ia-shared.ofed.test"],
			metadata: {
				federation_entity: {
					federation_registration_endpoint: "https://op.ofed.test/federation_registration",
				},
				openid_provider: {
					issuer: "https://op.ofed.test",
					authorization_endpoint: "https://op.ofed.test/auth",
					token_endpoint: "https://op.ofed.test/token",
					response_types_supported: ["code"],
					subject_types_supported: ["public"],
					id_token_signing_alg_values_supported: ["ES256"],
					client_registration_types_supported: ["automatic", "explicit"],
				},
			},
		},
		{
			id: "https://rp1.ofed.test",
			role: "leaf",
			protocolRole: "rp",
			authorityHints: ["https://ia-shared.ofed.test"],
			metadata: {
				openid_relying_party: {
					redirect_uris: ["https://rp1.ofed.test/callback"],
					response_types: ["code"],
					grant_types: ["authorization_code"],
					client_registration_types: ["automatic"],
					token_endpoint_auth_method: "private_key_jwt",
				},
			},
		},
		{
			id: "https://rp2.ofed.test",
			role: "leaf",
			protocolRole: "rp",
			authorityHints: ["https://ia-shared.ofed.test"],
			metadata: {
				openid_relying_party: {
					redirect_uris: ["https://rp2.ofed.test/callback"],
					response_types: ["code"],
					grant_types: ["authorization_code"],
					client_registration_types: ["explicit"],
					token_endpoint_auth_method: "private_key_jwt",
				},
			},
		},
	],
};
