import { JwtTyp, WELL_KNOWN_OPENID_FEDERATION } from "../../src/constants.js";
import { generateSigningKey } from "../../src/jose/keys.js";
import { signEntityStatement } from "../../src/jose/sign.js";
import type { JWK } from "../../src/schemas/jwk.js";
import type { FederationOptions, HttpClient, TrustAnchorSet } from "../../src/types.js";
import { LEAF_ID, OP_ID, TA_ID } from "./entity-ids.js";
import { createMockTrustAnchors } from "./mock-trust-anchors.js";

function signOpts(key: JWK): { kid?: string; typ: string } {
	return key.kid != null
		? { kid: key.kid, typ: JwtTyp.EntityStatement }
		: { typ: JwtTyp.EntityStatement };
}

export interface MockFederation {
	taSigningKey: JWK;
	taPublicKey: JWK;
	opSigningKey: JWK;
	opPublicKey: JWK;
	leafSigningKey: JWK;
	leafPublicKey: JWK;
	trustAnchors: TrustAnchorSet;
	taEcJwt: string;
	opEcJwt: string;
	leafEcJwt: string;
	taSubStatementForOp: string;
	taSubStatementForLeaf: string;
	httpClient: HttpClient;
	options: FederationOptions;
}

/** Builds a complete 3-entity federation (TA, OP, RP) with signed ECs, subordinate statements, and a mock HTTP client. */
export async function createMockFederation(overrides?: {
	opMetadata?: Record<string, Record<string, unknown>>;
	leafMetadata?: Record<string, Record<string, unknown>>;
}): Promise<MockFederation> {
	const { privateKey: taSigningKey, publicKey: taPublicKey } = await generateSigningKey("ES256");
	const { privateKey: opSigningKey, publicKey: opPublicKey } = await generateSigningKey("ES256");
	const { privateKey: leafSigningKey, publicKey: leafPublicKey } =
		await generateSigningKey("ES256");

	const now = Math.floor(Date.now() / 1000);
	const exp = now + 86400;

	// TA Entity Configuration (self-signed, iss===sub===TA_ID)
	const taEcPayload = {
		iss: TA_ID,
		sub: TA_ID,
		iat: now,
		exp,
		jwks: { keys: [taPublicKey] },
		metadata: {
			federation_entity: {
				federation_fetch_endpoint: `${TA_ID}/federation_fetch`,
				federation_list_endpoint: `${TA_ID}/federation_list`,
			},
		},
	};
	const taEcJwt = await signEntityStatement(taEcPayload, taSigningKey, signOpts(taSigningKey));

	// OP Entity Configuration (self-signed)
	const opMetadata = overrides?.opMetadata ?? {
		openid_provider: {
			issuer: OP_ID,
			authorization_endpoint: `${OP_ID}/authorize`,
			token_endpoint: `${OP_ID}/token`,
			response_types_supported: ["code"],
			subject_types_supported: ["public"],
			id_token_signing_alg_values_supported: ["ES256"],
			client_registration_types_supported: ["automatic", "explicit"],
		},
		federation_entity: {
			federation_registration_endpoint: `${OP_ID}/federation_registration`,
		},
	};
	const opEcPayload = {
		iss: OP_ID,
		sub: OP_ID,
		iat: now,
		exp,
		jwks: { keys: [opPublicKey] },
		authority_hints: [TA_ID],
		metadata: opMetadata,
	};
	const opEcJwt = await signEntityStatement(opEcPayload, opSigningKey, signOpts(opSigningKey));

	// Leaf Entity Configuration (self-signed)
	const leafMetadata = overrides?.leafMetadata ?? {
		openid_relying_party: {
			redirect_uris: ["https://rp.example.com/callback"],
			response_types: ["code"],
			client_registration_types: ["automatic"],
		},
	};
	const leafEcPayload = {
		iss: LEAF_ID,
		sub: LEAF_ID,
		iat: now,
		exp,
		jwks: { keys: [leafPublicKey] },
		authority_hints: [TA_ID],
		metadata: leafMetadata,
	};
	const leafEcJwt = await signEntityStatement(
		leafEcPayload,
		leafSigningKey,
		signOpts(leafSigningKey),
	);

	// TA subordinate statement about OP (signed by TA)
	const taSubStatementForOp = await signEntityStatement(
		{
			iss: TA_ID,
			sub: OP_ID,
			iat: now,
			exp,
			jwks: { keys: [opPublicKey] },
		},
		taSigningKey,
		signOpts(taSigningKey),
	);

	// TA subordinate statement about leaf RP (signed by TA)
	const taSubStatementForLeaf = await signEntityStatement(
		{
			iss: TA_ID,
			sub: LEAF_ID,
			iat: now,
			exp,
			jwks: { keys: [leafPublicKey] },
		},
		taSigningKey,
		signOpts(taSigningKey),
	);

	const trustAnchors = createMockTrustAnchors(TA_ID, taPublicKey);

	// Mock HTTP client: serves ECs at well-known and subordinate statements at fetch endpoint
	const httpClient: HttpClient = async (input: string | URL | Request): Promise<Response> => {
		const url =
			typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
		const parsed = new URL(url);

		// Entity Configuration requests
		if (parsed.pathname === WELL_KNOWN_OPENID_FEDERATION) {
			const origin = parsed.origin;
			if (origin === TA_ID) {
				return new Response(taEcJwt, {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				});
			}
			if (origin === OP_ID) {
				return new Response(opEcJwt, {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				});
			}
			if (origin === LEAF_ID) {
				return new Response(leafEcJwt, {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				});
			}
		}

		// Federation fetch endpoint (subordinate statements)
		if (parsed.pathname === "/federation_fetch") {
			const sub = parsed.searchParams.get("sub");
			const origin = parsed.origin;
			if (origin === TA_ID && sub === (OP_ID as string)) {
				return new Response(taSubStatementForOp, {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				});
			}
			if (origin === TA_ID && sub === (LEAF_ID as string)) {
				return new Response(taSubStatementForLeaf, {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				});
			}
		}

		return new Response("Not Found", { status: 404 });
	};

	const options: FederationOptions = { httpClient };

	return {
		taSigningKey,
		taPublicKey,
		opSigningKey,
		opPublicKey,
		leafSigningKey,
		leafPublicKey,
		trustAnchors,
		taEcJwt,
		opEcJwt,
		leafEcJwt,
		taSubStatementForOp,
		taSubStatementForLeaf,
		httpClient,
		options,
	};
}
