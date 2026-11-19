import {
	assertVerificationKey,
	createJwsAlgorithmRegistry,
	type CryptoEngine,
	CryptoError,
	type PublicJwk,
	type Signer,
	StaticKeyring,
} from "@oidfed/crypto";
import { createWebCryptoEngine } from "@oidfed/crypto/web";

/** Example private-use profile with an explicit public wire format and P-256 signatures. */
export const profileAlgorithm = "urn:example:jws:profile-p256";
const profileKeyType = "urn:example:jwk:profile-p256";

function p256PublicKey(key: PublicJwk): PublicJwk {
	const { u, v, kid } = key;
	if (typeof u !== "string" || typeof v !== "string")
		throw new CryptoError("MALFORMED_KEY", "Profile public keys require u and v");
	return { kty: "EC", crv: "P-256", x: u, y: v, alg: "ES256", kid };
}

export const algorithmRegistry = createJwsAlgorithmRegistry({
	keyTypes: [{
		keyType: profileKeyType,
		publicMembers: ["u", "v"],
		thumbprintMembers: ["u", "v"],
		validatePublicKey(key) { assertVerificationKey(p256PublicKey(key), "ES256"); },
	}],
	algorithms: [{
		id: profileAlgorithm,
		keyType: profileKeyType,
		validatePublicKey() {}, // This profile uses every key in the registered format.
		signature: { byteLength: 64 },
	}],
});

export function createProfileEngine(base = createWebCryptoEngine()): CryptoEngine {
	if (!base.algorithms.includes("ES256")) throw new Error("The profile requires a P-256 backend");
	return {
		algorithms: Object.freeze([...base.algorithms, profileAlgorithm]),
		digest: base.digest.bind(base),
		random: base.random.bind(base),
		async validatePublicKey(key, algorithm) {
			if (algorithm !== profileAlgorithm) return base.validatePublicKey(key, algorithm);
			const publicKey = assertVerificationKey(key, algorithm, algorithmRegistry);
			await base.validatePublicKey(p256PublicKey(publicKey), "ES256");
		},
		async verify(input) {
			if (input.algorithm !== profileAlgorithm) return base.verify(input);
			const publicKey = assertVerificationKey(input.key, input.algorithm, algorithmRegistry);
			return base.verify({ ...input, algorithm: "ES256", key: p256PublicKey(publicKey) });
		},
	};
}

/** Bind an existing opaque P-256 signing handle to the profile's public representation. */
export function profileSigner(kid: string, p256: Signer): Signer {
	const key = assertVerificationKey(p256.publicJwk, "ES256");
	return {
		publicJwk: { kid, kty: profileKeyType, alg: profileAlgorithm, use: "sig", u: key.x, v: key.y },
		sign: p256.sign.bind(p256),
	};
}

export function createProfileCrypto(p256: Signer) {
	const engine = createProfileEngine();
	const keyring = new StaticKeyring({
		algorithmRegistry,
		signers: { federation: profileSigner("profile-2026", p256) },
	});
	return {
		crypto: { engine, keyring, algorithmRegistry },
		options: { allowedFederationAlgorithms: ["RS256", profileAlgorithm] },
	};
}
