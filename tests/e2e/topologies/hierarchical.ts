import type { TopologyDefinition } from "./types.js";

export const hierarchicalTopology: TopologyDefinition = {
	name: "hierarchical",
	description: "TA → 2 Intermediates (edu, health), each with OP + RP",
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
			id: "https://ia-edu.ofed.test",
			role: "intermediate",
			authorityHints: ["https://ta.ofed.test"],
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: "https://ia-edu.ofed.test/federation_fetch",
					federation_list_endpoint: "https://ia-edu.ofed.test/federation_list",
					federation_resolve_endpoint: "https://ia-edu.ofed.test/federation_resolve",
					federation_historical_keys_endpoint:
						"https://ia-edu.ofed.test/federation_historical_keys",
				},
			},
			metadataPolicy: {
				openid_provider: {
					token_endpoint_auth_methods_supported: { default: ["private_key_jwt"] },
				},
			},
		},
		{
			id: "https://ia-health.ofed.test",
			role: "intermediate",
			authorityHints: ["https://ta.ofed.test"],
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: "https://ia-health.ofed.test/federation_fetch",
					federation_list_endpoint: "https://ia-health.ofed.test/federation_list",
					federation_resolve_endpoint: "https://ia-health.ofed.test/federation_resolve",
					federation_historical_keys_endpoint:
						"https://ia-health.ofed.test/federation_historical_keys",
				},
			},
			metadataPolicy: {
				openid_provider: {
					token_endpoint_auth_methods_supported: { default: ["private_key_jwt"] },
				},
			},
		},
		{
			id: "https://op-uni.ofed.test",
			role: "leaf",
			protocolRole: "op",
			authorityHints: ["https://ia-edu.ofed.test"],
			metadata: {
				federation_entity: {
					federation_registration_endpoint: "https://op-uni.ofed.test/federation_registration",
				},
				openid_provider: {
					issuer: "https://op-uni.ofed.test",
					authorization_endpoint: "https://op-uni.ofed.test/auth",
					token_endpoint: "https://op-uni.ofed.test/token",
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
			authorityHints: ["https://ia-edu.ofed.test"],
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
			id: "https://op-hospital.ofed.test",
			role: "leaf",
			protocolRole: "op",
			authorityHints: ["https://ia-health.ofed.test"],
			metadata: {
				federation_entity: {
					federation_registration_endpoint: "https://op-hospital.ofed.test/federation_registration",
				},
				openid_provider: {
					issuer: "https://op-hospital.ofed.test",
					authorization_endpoint: "https://op-hospital.ofed.test/auth",
					token_endpoint: "https://op-hospital.ofed.test/token",
					response_types_supported: ["code"],
					subject_types_supported: ["public"],
					id_token_signing_alg_values_supported: ["ES256"],
					client_registration_types_supported: ["automatic", "explicit"],
				},
			},
		},
		{
			id: "https://rp2.ofed.test",
			role: "leaf",
			protocolRole: "rp",
			authorityHints: ["https://ia-health.ofed.test"],
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
