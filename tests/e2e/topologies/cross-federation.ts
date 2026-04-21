import type { TopologyDefinition } from "./types.js";

export const crossFederationTopology: TopologyDefinition = {
	name: "cross-federation",
	description: "2 federations (X, Y) linked by a bridge entity",
	entities: [
		// Federation X
		{
			id: "https://ta-x.ofed.test",
			role: "trust-anchor",
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: "https://ta-x.ofed.test/federation_fetch",
					federation_list_endpoint: "https://ta-x.ofed.test/federation_list",
					federation_resolve_endpoint: "https://ta-x.ofed.test/federation_resolve",
					federation_historical_keys_endpoint: "https://ta-x.ofed.test/federation_historical_keys",
				},
			},
		},
		{
			id: "https://ia-x.ofed.test",
			role: "intermediate",
			authorityHints: ["https://ta-x.ofed.test"],
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: "https://ia-x.ofed.test/federation_fetch",
					federation_list_endpoint: "https://ia-x.ofed.test/federation_list",
					federation_resolve_endpoint: "https://ia-x.ofed.test/federation_resolve",
					federation_historical_keys_endpoint: "https://ia-x.ofed.test/federation_historical_keys",
				},
			},
		},
		{
			id: "https://op-x.ofed.test",
			role: "leaf",
			protocolRole: "op",
			authorityHints: ["https://ia-x.ofed.test"],
			metadata: {
				federation_entity: {
					federation_registration_endpoint: "https://op-x.ofed.test/federation_registration",
				},
				openid_provider: {
					issuer: "https://op-x.ofed.test",
					authorization_endpoint: "https://op-x.ofed.test/auth",
					token_endpoint: "https://op-x.ofed.test/token",
					response_types_supported: ["code"],
					subject_types_supported: ["public"],
					id_token_signing_alg_values_supported: ["ES256"],
					client_registration_types_supported: ["automatic", "explicit"],
				},
			},
		},
		{
			id: "https://rp-x.ofed.test",
			role: "leaf",
			protocolRole: "rp",
			authorityHints: ["https://ia-x.ofed.test"],
			metadata: {
				openid_relying_party: {
					redirect_uris: ["https://rp-x.ofed.test/callback"],
					response_types: ["code"],
					grant_types: ["authorization_code"],
					client_registration_types: ["automatic"],
					token_endpoint_auth_method: "private_key_jwt",
				},
			},
		},
		// Federation Y
		{
			id: "https://ta-y.ofed.test",
			role: "trust-anchor",
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: "https://ta-y.ofed.test/federation_fetch",
					federation_list_endpoint: "https://ta-y.ofed.test/federation_list",
					federation_resolve_endpoint: "https://ta-y.ofed.test/federation_resolve",
					federation_historical_keys_endpoint: "https://ta-y.ofed.test/federation_historical_keys",
				},
			},
		},
		{
			id: "https://ia-y.ofed.test",
			role: "intermediate",
			authorityHints: ["https://ta-y.ofed.test"],
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: "https://ia-y.ofed.test/federation_fetch",
					federation_list_endpoint: "https://ia-y.ofed.test/federation_list",
					federation_resolve_endpoint: "https://ia-y.ofed.test/federation_resolve",
					federation_historical_keys_endpoint: "https://ia-y.ofed.test/federation_historical_keys",
				},
			},
		},
		{
			id: "https://op-y.ofed.test",
			role: "leaf",
			protocolRole: "op",
			authorityHints: ["https://ia-y.ofed.test"],
			metadata: {
				federation_entity: {
					federation_registration_endpoint: "https://op-y.ofed.test/federation_registration",
				},
				openid_provider: {
					issuer: "https://op-y.ofed.test",
					authorization_endpoint: "https://op-y.ofed.test/auth",
					token_endpoint: "https://op-y.ofed.test/token",
					response_types_supported: ["code"],
					subject_types_supported: ["public"],
					id_token_signing_alg_values_supported: ["ES256"],
					client_registration_types_supported: ["automatic", "explicit"],
				},
			},
		},
		{
			id: "https://rp-y.ofed.test",
			role: "leaf",
			protocolRole: "rp",
			authorityHints: ["https://ia-y.ofed.test"],
			metadata: {
				openid_relying_party: {
					redirect_uris: ["https://rp-y.ofed.test/callback"],
					response_types: ["code"],
					grant_types: ["authorization_code"],
					client_registration_types: ["automatic"],
					token_endpoint_auth_method: "private_key_jwt",
				},
			},
		},
		// Bridge: subordinate of both TA-X and TA-Y
		{
			id: "https://bridge.ofed.test",
			role: "intermediate",
			authorityHints: ["https://ta-x.ofed.test", "https://ta-y.ofed.test"],
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: "https://bridge.ofed.test/federation_fetch",
					federation_list_endpoint: "https://bridge.ofed.test/federation_list",
					federation_resolve_endpoint: "https://bridge.ofed.test/federation_resolve",
					federation_historical_keys_endpoint:
						"https://bridge.ofed.test/federation_historical_keys",
				},
			},
		},
	],
};
