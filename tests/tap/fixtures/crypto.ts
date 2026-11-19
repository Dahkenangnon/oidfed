/** Ephemeral software keys and byte-exact verification inputs for the crypto contract tests. */
import {
	type BuiltinJwsAlgorithm,
	type Jwk,
	type JwsVerifyInput,
	parseCompactJws,
} from "@oidfed/crypto";
import { SoftwareSigner } from "@oidfed/crypto/web";
import { exportJWK, generateKeyPair } from "jose";

const fixtures = new Map<BuiltinJwsAlgorithm, ReturnType<typeof generate>>();
async function generate(algorithm: BuiltinJwsAlgorithm) {
	const pair = await generateKeyPair(algorithm, { extractable: true });
	const privateJwk = {
		...(await exportJWK(pair.privateKey)),
		kid: `fixture-${algorithm}`,
		alg: algorithm,
	} as Jwk & { kid: string; alg: BuiltinJwsAlgorithm };
	const publicJwk = {
		...(await exportJWK(pair.publicKey)),
		kid: privateJwk.kid,
		alg: algorithm,
	} as Jwk;
	return { pair, privateJwk, publicJwk, signer: new SoftwareSigner(privateJwk) };
}
export function cryptoFixture(algorithm: BuiltinJwsAlgorithm = "ES256") {
	let fixture = fixtures.get(algorithm);
	if (!fixture) {
		fixture = generate(algorithm);
		fixtures.set(algorithm, fixture);
	}
	return fixture;
}
export function cryptoInput(compact: string, key: Jwk): JwsVerifyInput {
	const parsed = parseCompactJws(compact);
	return {
		algorithm: parsed.header.alg,
		key,
		signingInput: parsed.signingInput,
		signature: parsed.signature,
	};
}
