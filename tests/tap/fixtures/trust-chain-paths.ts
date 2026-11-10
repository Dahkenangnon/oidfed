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
	const entityConfigurations = new Map<string, string>();
	const chain = async (
		path: readonly [Name, ...Name[]],
		config: {
			includeAnchorEc?: boolean;
			subjectClaims?: Record<string, unknown>;
			anchorClaims?: Record<string, unknown>;
		} = {},
	) => {
		for (let i = 1; i < path.length - 1; i++) {
			const name = path[i] as Name;
			entityConfigurations.set(
				ids[name],
				await sign(name, name, {
					authority_hints: [ids[path[i + 1] as Name]],
				}),
			);
		}
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
			entityConfigurations,
			clock: { now: () => 1500 },
			clockSkewSeconds: 0,
			verboseErrors: true,
			httpClient: async () => {
				throw new Error("Supplied paths must validate offline");
			},
		},
	};
}

/** The configured key signs the anchor EC; a second published key signs its SS. */
export async function anchorKeyPaths(metadata: Record<string, Record<string, unknown>> = {}) {
	const f = await trustChainPaths(metadata);
	const chain = async (
		publication: "overlap" | "missing-signer" | "wrong-material",
		subjectClaims: Record<string, unknown> = {},
		anchorClaims: Record<string, unknown> = {},
	) => {
		const replacement = {
			publicKey: { ...f.keys.b.publicKey },
			privateKey: { ...f.keys.b.privateKey },
		};
		if (publication === "wrong-material") {
			replacement.publicKey.kid = f.keys.anchor.publicKey.kid;
			replacement.privateKey.kid = f.keys.anchor.privateKey.kid;
		}
		const result = await f.chain(["subject", "anchor"], { subjectClaims });
		result[1] = await signEntityStatement(
			{
				iss: f.ids.anchor,
				sub: f.ids.subject,
				iat: 1000,
				exp: 5000,
				jwks: { keys: [f.keys.subject.publicKey] },
			},
			new JwkSigner(replacement.privateKey),
		);
		result[2] = await f.sign("anchor", "anchor", {
			...anchorClaims,
			jwks: {
				keys:
					publication === "overlap"
						? [f.keys.anchor.publicKey, replacement.publicKey]
						: [replacement.publicKey],
			},
		});
		return result;
	};
	return { ...f, anchorKeyChain: chain };
}
