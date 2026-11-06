import {
	entityId,
	generateSigningKey,
	JwkSigner,
	signEntityStatement,
} from "../../../packages/core/src/index.js";
import { createMockTrustAnchors } from "./mock-trust-anchors.js";

/** Signed paths with independent keys and an offline validation clock. */
export async function trustChainPaths(
	metadata: Record<string, Record<string, unknown>> = {},
	sharedIntermediateKey = false,
) {
	const ids = {
		subject: entityId("https://subject.example"),
		a: entityId("https://a.example"),
		b: entityId("https://b.example"),
		anchor: entityId("https://anchor.example"),
	};
	const keys = {
		subject: await generateSigningKey(),
		a: await generateSigningKey(),
		b: await generateSigningKey(),
		anchor: await generateSigningKey(),
	};
	if (sharedIntermediateKey) keys.b = keys.a;
	type Name = keyof typeof ids;
	const sign = (issuer: Name, subject: Name, claims: Record<string, unknown> = {}) =>
		signEntityStatement(
			{
				iss: ids[issuer],
				sub: ids[subject],
				iat: 1000,
				exp: 5000,
				jwks: { keys: [keys[subject].publicKey] },
				...claims,
			},
			new JwkSigner(keys[issuer].privateKey),
		);
	const chain = async (
		path: readonly [Name, ...Name[]],
		config: {
			includeAnchorEc?: boolean;
			subjectClaims?: Record<string, unknown>;
			anchorClaims?: Record<string, unknown>;
		} = {},
	) => {
		const result = [
			await sign(path[0], path[0], {
				...(Object.keys(metadata).length ? { metadata } : {}),
				...(path[1] ? { authority_hints: [ids[path[1]]] } : config.anchorClaims),
				...config.subjectClaims,
			}),
		];
		for (let i = 1; i < path.length; i++)
			result.push(await sign(path[i] as Name, path[i - 1] as Name));
		if (path.length > 1 && config.includeAnchorEc !== false) {
			const last = path[path.length - 1] as Name;
			result.push(await sign(last, last, config.anchorClaims));
		}
		return result;
	};
	return {
		ids,
		keys,
		sign,
		chain,
		anchors: createMockTrustAnchors(ids.anchor, keys.anchor.publicKey),
		options: {
			clock: { now: () => 1500 },
			clockSkewSeconds: 0,
			verboseErrors: true,
			httpClient: async () => {
				throw new Error("Supplied paths must validate offline");
			},
		},
	};
}
