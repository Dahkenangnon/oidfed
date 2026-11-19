import type { KeyringEntry } from "@oidfed/crypto";
import { encodeBase64url, utf8Encode } from "@oidfed/crypto";
import type { SignEntityStatementOptions } from "../../../packages/core/src/index.js";

/** Sign exact test headers, including malformed envelopes and optional protocol key identifiers. */
export function signProtocolFixture(
	payload: Record<string, unknown>,
	signer: KeyringEntry,
	options?: SignEntityStatementOptions,
): Promise<string> {
	const header = {
		alg: signer.signer.publicJwk.alg,
		kid: signer.signer.publicJwk.kid,
		typ: options?.typ ?? "entity-statement+jwt",
		...options?.extraHeaders,
	};
	const input = `${encodeBase64url(utf8Encode(JSON.stringify(header)))}.${encodeBase64url(utf8Encode(JSON.stringify(payload)))}`;
	return signer.signer
		.sign(utf8Encode(input))
		.then((signature) => `${input}.${encodeBase64url(signature)}`);
}
