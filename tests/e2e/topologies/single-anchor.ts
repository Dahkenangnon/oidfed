import type { TopologyDefinition } from "./types.js";

export const singleAnchorTopology: TopologyDefinition = {
	name: "single-anchor",
	description: "Minimal topology: 1 TA, 1 OP, 2 RPs (automatic + explicit)",
	entities: [
		{
			id: "https://ta.ofed.test",
			role: "trust-anchor",
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: "https://ta.ofed.test/federation_fetch",
					federation_list_endpoint: "https://ta.ofed.test/federation_list",
					federation_resolve_endpoint: "https://ta.ofed.test/federation_resolve",
					federation_trust_mark_endpoint: "https://ta.ofed.test/federation_trust_mark",
					federation_trust_mark_status_endpoint:
						"https://ta.ofed.test/federation_trust_mark_status",
					federation_trust_mark_list_endpoint: "https://ta.ofed.test/federation_trust_mark_list",
					federation_historical_keys_endpoint: "https://ta.ofed.test/federation_historical_keys",
				},
			},
			trustMarkIssuers: {
				"https://ta.ofed.test/trust-marks/certified": ["https://ta.ofed.test"],
			},
		},
		{
			id: "https://op.ofed.test",
			role: "leaf",
			protocolRole: "op",
			authorityHints: ["https://ta.ofed.test"],
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
			id: "https://rp.ofed.test",
			role: "leaf",
			protocolRole: "rp",
			authorityHints: ["https://ta.ofed.test"],
			metadata: {
				openid_relying_party: {
					redirect_uris: ["https://rp.ofed.test/callback"],
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
			authorityHints: ["https://ta.ofed.test"],
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
