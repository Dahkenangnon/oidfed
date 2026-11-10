import {
	createTrustAnchorSet,
	decodeEntityStatement,
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
		issuerServerMetadata?: Record<string, unknown>;
		serverMetadata?: Record<string, unknown>;
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
			oauth_authorization_server: {
				issuer: ids.issuer,
				authorization_details_types_supported: ["openid_credential"],
				...config.issuerServerMetadata,
			},
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
		server: {
			oauth_authorization_server: {
				issuer: ids.server,
				authorization_details_types_supported: ["openid_credential"],
				...config.serverMetadata,
			},
		},
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

/** The same wallet roles below one intermediate, with separately supplied EC evidence. */
export async function hierarchicalWalletFederation(
	config?: Parameters<typeof walletFederation>[0],
) {
	const f = await walletFederation(config);
	const intermediate = {
		id: entityId("https://intermediate.example"),
		keys: await generateSigningKey(),
	};
	const sign = (payload: Record<string, unknown>) =>
		signEntityStatement(
			{ iat: 1000, exp: 5000, ...payload },
			new JwkSigner(intermediate.keys.privateKey),
		);
	const response = (jwt: string) => () =>
		new Response(jwt, { headers: { "content-type": "application/entity-statement+jwt" } });
	const ec = await sign({
		iss: intermediate.id,
		sub: intermediate.id,
		jwks: { keys: [intermediate.keys.publicKey] },
		authority_hints: [f.ids.anchor],
		metadata: { federation_entity: { federation_fetch_endpoint: `${intermediate.id}/fetch` } },
	});
	const ss = await signEntityStatement(
		{
			iss: f.ids.anchor,
			sub: intermediate.id,
			iat: 1000,
			exp: 5000,
			jwks: { keys: [intermediate.keys.publicKey] },
		},
		new JwkSigner(f.keys.anchor.privateKey),
	);
	f.routes.set(`${intermediate.id}/.well-known/openid-federation`, response(ec));
	f.routes.set(`${f.ids.anchor}/fetch?sub=${encodeURIComponent(intermediate.id)}`, response(ss));
	for (const name of ["provider", "issuer", "verifier", "server"] as const) {
		const chain = f.chains.get(f.ids[name])!;
		const leaf = decodeEntityStatement(chain[0]!);
		const statement = decodeEntityStatement(chain[1]!);
		if (!leaf.ok || !statement.ok) throw new Error("Invalid wallet fixture");
		const leafEc = await signEntityStatement(
			{ ...leaf.value.payload, authority_hints: [intermediate.id] },
			new JwkSigner(f.keys[name].privateKey),
		);
		const leafSs = await sign({ ...statement.value.payload, iss: intermediate.id });
		f.chains.set(f.ids[name], [leafEc, leafSs, ss, chain[2]!]);
		f.routes.set(`${f.ids[name]}/.well-known/openid-federation`, response(leafEc));
		f.routes.set(
			`${intermediate.id}/fetch?sub=${encodeURIComponent(f.ids[name])}`,
			response(leafSs),
		);
	}
	return { ...f, intermediate, entityConfigurations: new Map([[intermediate.id, ec]]) };
}
