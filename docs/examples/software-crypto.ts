/** Optional Web Crypto setup for the documentation examples. Applications own this code. */
import {
	encodeBase64url,
	jwkThumbprint,
	MemoryRotatingKeyring,
	StaticKeyring,
	type Jwk,
	type BuiltinJwsAlgorithm,
} from "@oidfed/crypto";
import { createWebCryptoEngine, SoftwareSigner } from "@oidfed/crypto/web";
import { historicalKeysFromKeyring } from "@oidfed/core";

export const engine = createWebCryptoEngine();

/** Example software key generation. Persist deployment keys or use an opaque host signer. */
export async function generateSoftwareKey(alg: BuiltinJwsAlgorithm = "ES256") {
	const algorithm = alg.startsWith("ES")
		? {
				name: "ECDSA",
				namedCurve: ({ ES256: "P-256", ES384: "P-384", ES512: "P-521" } as const)[
					alg as "ES256" | "ES384" | "ES512"
				],
			}
		: alg.startsWith("Ed")
			? { name: "Ed25519" }
			: {
					name: alg.startsWith("PS") ? "RSA-PSS" : "RSASSA-PKCS1-v1_5",
					hash: `SHA-${alg.slice(2)}`,
					modulusLength: 2048,
					publicExponent: new Uint8Array([1, 0, 1]),
				};
	const pair = (await crypto.subtle.generateKey(algorithm, true, [
		"sign",
		"verify",
	])) as CryptoKeyPair;
	const publicKey = await crypto.subtle.exportKey("jwk", pair.publicKey);
	const kid = encodeBase64url(await jwkThumbprint(engine, publicKey as Jwk));
	return {
		publicKey: { ...publicKey, kty: publicKey.kty!, kid, alg, use: "sig" },
		privateKey: {
			...(await crypto.subtle.exportKey("jwk", pair.privateKey)),
			kty: publicKey.kty!,
			kid,
			alg,
			use: "sig",
		},
	};
}

/** Capture one software signing binding; protocol helpers consume this entry. */
export function softwareEntry(key: Jwk) {
	const signer = new SoftwareSigner({ ...key, kid: key.kid!, alg: key.alg as BuiltinJwsAlgorithm });
	return { signer, publishedJwks: { keys: [signer.publicJwk] } };
}

/** Example context with separate Federation and optional OIDC protocol keys. */
export function softwareCrypto(federationKey: Jwk, protocolKey?: Jwk) {
	const keyring = new MemoryRotatingKeyring({ federation: softwareEntry(federationKey).signer });
	if (!protocolKey) return { engine, keyring, history: historicalKeysFromKeyring(keyring) };
	const protocol = new StaticKeyring({
		signers: { request_object: softwareEntry(protocolKey).signer },
		aliases: { client_assertion: "request_object" },
	});
	return {
		engine,
		keyring: {
			entry: (purpose: string) =>
				purpose === "federation" ? keyring.entry(purpose) : protocol.entry(purpose),
		},
		history: historicalKeysFromKeyring(keyring),
	};
}
