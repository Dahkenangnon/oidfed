/** Explicit software crypto setup for this Node application. */
import {
	type BuiltinJwsAlgorithm,
	encodeBase64url,
	type Jwk,
	jwkThumbprint,
	StaticKeyring,
} from "@oidfed/crypto";
import { createWebCryptoEngine, SoftwareSigner } from "@oidfed/crypto/web";

/** Backend owned by the CLI, never initialized by a library import. */
export const engine = createWebCryptoEngine();

/** Generate exportable software keys for the keygen command. */
export async function generateSigningKey(
	alg: BuiltinJwsAlgorithm = "ES256",
): Promise<{ publicKey: Jwk; privateKey: Jwk }> {
	const curves = { ES256: "P-256", ES384: "P-384", ES512: "P-521" };
	const algorithm = alg.startsWith("ES")
		? { name: "ECDSA", namedCurve: curves[alg as keyof typeof curves] }
		: alg.startsWith("Ed")
			? { name: "Ed25519" }
			: {
					name: alg.startsWith("PS") ? "RSA-PSS" : "RSASSA-PKCS1-v1_5",
					modulusLength: 2048,
					publicExponent: new Uint8Array([1, 0, 1]),
					hash: `SHA-${alg.slice(2)}`,
				};
	const pair = (await crypto.subtle.generateKey(algorithm, true, ["sign", "verify"])) as {
		publicKey: import("node:crypto").webcrypto.CryptoKey;
		privateKey: import("node:crypto").webcrypto.CryptoKey;
	};
	const publicJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
	const kid = encodeBase64url(await jwkThumbprint(engine, publicJwk as unknown as Jwk));
	return {
		publicKey: { ...publicJwk, kty: publicJwk.kty as string, alg, kid, use: "sig" },
		privateKey: {
			...(await crypto.subtle.exportKey("jwk", pair.privateKey)),
			kty: publicJwk.kty as string,
			alg,
			kid,
			use: "sig",
		},
	};
}

/** Capture an explicit software signer as an immutable one-purpose snapshot. */
export function softwareEntry(privateKey: Jwk, algorithm = privateKey.alg) {
	const signer = new SoftwareSigner({
		...privateKey,
		kid: privateKey.kid as string,
		alg: algorithm as BuiltinJwsAlgorithm,
	});
	return new StaticKeyring({ signers: { federation: signer } }).entry("federation");
}
