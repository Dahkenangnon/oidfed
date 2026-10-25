import {
	createTrustAnchorSet,
	entityId,
	generateSigningKey,
	type HttpClient,
	JwkSigner,
	signEntityStatement,
} from "../../../packages/core/src/index.js";

export interface CollectionGraphEdge {
	issuer: string;
	subject: string;
	constraints?: Record<string, unknown>;
	expiresAt?: number;
}

/** Signed graphs exercise collection without depending on authority storage or routing. */
export async function createCollectionFederation(config: {
	edges: readonly CollectionGraphEdge[];
	ids?: Record<string, string>;
	listOrder?: Record<string, readonly string[]>;
	marked?: boolean;
	badKeyEdge?: string;
}) {
	const names = [
		...new Set(["ta", ...config.edges.flatMap((edge) => [edge.issuer, edge.subject])]),
	];
	const ids = new Map(
		names.map((name) => [name, entityId(config.ids?.[name] ?? `https://${name}.example`)]),
	);
	const id = (name: string) => {
		const value = ids.get(name);
		if (!value) throw new Error(`Unknown graph entity ${name}`);
		return value;
	};
	const keys = new Map(
		await Promise.all(
			names.map(async (name) => [name, await generateSigningKey("ES256")] as const),
		),
	);
	const sign = (name: string, payload: Record<string, unknown>, typ?: string) =>
		signEntityStatement(
			{ iat: 1000, exp: 5000, ...payload },
			new JwkSigner(keys.get(name)!.privateKey),
			typ ? { typ } : undefined,
		);
	const mark = config.marked
		? await sign(
				"issuer",
				{ iss: id("issuer"), sub: id("leaf"), trust_mark_type: "one", exp: 4000 },
				"trust-mark+jwt",
			)
		: undefined;
	const routes = new Map<string, () => Response>();
	const configurations = new Map<string, string>();
	const statements = new Map<string, string>();
	for (const name of names) {
		const children = config.edges
			.filter((edge) => edge.issuer === name)
			.map((edge) => id(edge.subject));
		const parents = config.edges
			.filter((edge) => edge.subject === name)
			.map((edge) => id(edge.issuer));
		const jwt = await sign(name, {
			iss: id(name),
			sub: id(name),
			jwks: { keys: [keys.get(name)!.publicKey] },
			...(name === "ta"
				? config.marked
					? { trust_mark_issuers: { one: [id("issuer")] } }
					: {}
				: { authority_hints: parents }),
			metadata: {
				federation_entity: children.length
					? {
							federation_fetch_endpoint: `${id(name)}/fetch`,
							federation_list_endpoint: `${id(name)}/list`,
						}
					: {},
			},
			...(name === "leaf" && mark
				? { trust_marks: [{ trust_mark_type: "one", trust_mark: mark }] }
				: {}),
		});
		configurations.set(name, jwt);
		routes.set(
			`${id(name)}/.well-known/openid-federation`,
			() => new Response(jwt, { headers: { "content-type": "application/entity-statement+jwt" } }),
		);
		routes.set(
			`${id(name)}/list`,
			() =>
				new Response(JSON.stringify(config.listOrder?.[name]?.map(id) ?? children), {
					headers: { "content-type": "application/json" },
				}),
		);
	}
	for (const edge of config.edges)
		statements.set(
			`${id(edge.issuer)}|${id(edge.subject)}`,
			await sign(edge.issuer, {
				iss: id(edge.issuer),
				sub: id(edge.subject),
				jwks: {
					keys: [
						keys.get(config.badKeyEdge === `${edge.issuer}|${edge.subject}` ? "ta" : edge.subject)!
							.publicKey,
					],
				},
				...(edge.constraints ? { constraints: edge.constraints } : {}),
				...(edge.expiresAt !== undefined ? { exp: edge.expiresAt } : {}),
			}),
		);
	const requests: string[] = [];
	const httpClient: HttpClient = async (input) => {
		const url = new URL(String(input));
		requests.push(url.toString());
		const bare = url.origin + url.pathname;
		const route = routes.get(bare);
		if (route) return route();
		const issuer = names.find((name) => `${id(name)}/fetch` === bare);
		const jwt = issuer ? statements.get(`${id(issuer)}|${url.searchParams.get("sub")}`) : undefined;
		return new Response(jwt ?? "", {
			status: jwt ? 200 : 404,
			headers: { "content-type": "application/entity-statement+jwt" },
		});
	};
	return {
		id,
		configurations,
		statements,
		requests,
		httpClient,
		routes,
		keys,
		trustAnchors: createTrustAnchorSet([
			{ entityId: id("ta"), jwks: { keys: [keys.get("ta")!.publicKey] } },
		]),
	};
}
