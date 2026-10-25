import {
	createTrustAnchorSet,
	entityId,
	generateSigningKey,
	type HttpClient,
	JwkSigner,
	signEntityStatement,
} from "../../../packages/core/src/index.js";

export const walletQuery = {
	credentials: [
		{ id: "identity", format: "dc+sd-jwt", meta: { vct_values: ["https://example.com/identity"] } },
	],
};

/** Federation and protocol keys are intentionally distinct in every fixture. */
export async function walletFederation(
	config: {
		policy?: Record<string, Record<string, unknown>>;
		verifierMetadata?: Record<string, unknown>;
		verifierOverride?: Record<string, unknown>;
		issuerMetadata?: Record<string, unknown>;
		providerMetadata?: Record<string, unknown>;
	} = {},
) {
	let time = 1500;
	const clock = { now: () => time };
	const ids = {
		anchor: entityId("https://anchor.example"),
		provider: entityId("https://provider.example"),
		issuer: entityId("https://issuer.example"),
		verifier: entityId("https://verifier.example"),
		server: entityId("https://server.example"),
	};
	const keys = {
		anchor: await generateSigningKey(),
		provider: await generateSigningKey(),
		issuer: await generateSigningKey(),
		verifier: await generateSigningKey(),
		server: await generateSigningKey(),
	};
	const protocol = {
		provider: await generateSigningKey(),
		issuer: await generateSigningKey(),
		verifier: await generateSigningKey(),
	};
	const sign = (name: keyof typeof keys, payload: Record<string, unknown>, typ?: string) =>
		signEntityStatement(
			{ iat: 1000, exp: 5000, ...payload },
			new JwkSigner(keys[name].privateKey),
			typ ? { typ } : undefined,
		);
	const anchorJwt = await sign("anchor", {
		iss: ids.anchor,
		sub: ids.anchor,
		jwks: { keys: [keys.anchor.publicKey] },
		metadata: {
			federation_entity: {
				federation_fetch_endpoint: `${ids.anchor}/fetch`,
				federation_list_endpoint: `${ids.anchor}/list`,
			},
		},
	});
	const metadata: Record<
		Exclude<keyof typeof ids, "anchor">,
		Record<string, Record<string, unknown>>
	> = {
		provider: {
			openid_wallet_provider: {
				vp_formats_supported: { "dc+sd-jwt": {} },
				jwks: { keys: [protocol.provider.publicKey] },
				...config.providerMetadata,
			},
		},
		issuer: {
			openid_credential_issuer: {
				credential_issuer: ids.issuer,
				credential_endpoint: `${ids.issuer}/credentials`,
				credential_configurations_supported: {
					identity: { format: "dc+sd-jwt", vct: "https://example.com/identity" },
				},
				jwks: { keys: [protocol.issuer.publicKey] },
				...config.issuerMetadata,
			},
			oauth_authorization_server: { issuer: ids.issuer },
		},
		verifier: {
			openid_credential_verifier: {
				vp_formats_supported: { "dc+sd-jwt": {} },
				jwks: { keys: [protocol.verifier.publicKey] },
				request_uris: [`${ids.verifier}/request`],
				response_uris: [`${ids.verifier}/response`],
				redirect_uris: [`${ids.verifier}/done`],
				...config.verifierMetadata,
			},
		},
		server: { oauth_authorization_server: { issuer: ids.server } },
	};
	const chains = new Map<string, readonly string[]>();
	const routes = new Map<string, () => Response>();
	routes.set(
		`${ids.anchor}/.well-known/openid-federation`,
		() =>
			new Response(anchorJwt, { headers: { "content-type": "application/entity-statement+jwt" } }),
	);
	for (const name of ["provider", "issuer", "verifier", "server"] as const) {
		const ec = await sign(name, {
			iss: ids[name],
			sub: ids[name],
			jwks: { keys: [keys[name].publicKey] },
			authority_hints: [ids.anchor],
			metadata: metadata[name],
		});
		const ss = await sign("anchor", {
			iss: ids.anchor,
			sub: ids[name],
			jwks: { keys: [keys[name].publicKey] },
			...(name === "verifier" && config.policy
				? { metadata_policy: { openid_credential_verifier: config.policy } }
				: {}),
			...(name === "verifier" && config.verifierOverride
				? { metadata: { openid_credential_verifier: config.verifierOverride } }
				: {}),
		});
		chains.set(ids[name], [ec, ss, anchorJwt]);
		routes.set(
			`${ids[name]}/.well-known/openid-federation`,
			() => new Response(ec, { headers: { "content-type": "application/entity-statement+jwt" } }),
		);
		routes.set(
			`${ids.anchor}/fetch?sub=${encodeURIComponent(ids[name])}`,
			() => new Response(ss, { headers: { "content-type": "application/entity-statement+jwt" } }),
		);
	}
	const requests: string[] = [];
	const httpClient: HttpClient = async (input) => {
		const url = String(input);
		requests.push(url);
		return routes.get(url)?.() ?? new Response("not found", { status: 404 });
	};
	const anchors = createTrustAnchorSet([
		{ entityId: ids.anchor, jwks: { keys: [keys.anchor.publicKey] } },
	]);
	return {
		ids,
		keys,
		protocol,
		metadata,
		chains,
		anchors,
		clock,
		httpClient,
		requests,
		routes,
		setTime: (value: number) => {
			time = value;
		},
		options: { clock, clockSkewSeconds: 0, httpClient, entityChains: chains },
		requestPayload: {
			client_id: `openid_federation:${ids.verifier}`,
			response_type: "vp_token",
			response_mode: "direct_post",
			response_uri: `${ids.verifier}/response`,
			nonce: "session-nonce",
			dcql_query: walletQuery,
			aud: "https://self-issued.me/v2",
			iat: 1400,
			exp: 2000,
		},
	};
}
