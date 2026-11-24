/** Entity Statement verification and explicitly unverified decoding. */
import { decodeCompactJws, type FederationArtifact } from "@oidfed/crypto";
import { InternalErrorCode, JwtTyp } from "../constants.js";
import { federationJwsOptions } from "../crypto-context.js";
import { err, type FederationError, ok, type Result } from "../errors.js";
import { JwsService, type JwsServiceOptions } from "../jws-service.js";
import {
	type EntityConfigurationPayload,
	EntityConfigurationSchema,
	type SubordinateStatementPayload,
	SubordinateStatementSchema,
} from "../schemas/entity-statement.js";
import type { JWKSet } from "../schemas/jwk.js";
import type {
	FederationOptions,
	ParsedEntityStatement,
	UnverifiedEntityStatement,
} from "../types.js";

/** Compact verification options for signatures made with Federation Entity Keys. */
export interface FederationJwsOptions extends Omit<JwsServiceOptions, "allowedAlgorithms"> {
	readonly allowedFederationAlgorithms?: readonly string[] | undefined;
	readonly allowedAlgorithmsForArtifact?: FederationOptions["allowedAlgorithmsForArtifact"];
	/** The expected operation from trusted context. Required with an artifact policy. */
	readonly artifact?: FederationArtifact | undefined;
}

/** Verify signature and generic JWT claims; protocol schemas remain separate. */
export async function verifyEntityStatement(
	jwt: string,
	jwks: JWKSet,
	options: FederationJwsOptions & { readonly expectedTyp?: string },
): Promise<Result<ParsedEntityStatement>> {
	let scoped: JwsServiceOptions;
	try {
		scoped = federationJwsOptions(options, options.artifact);
	} catch {
		return err({
			code: InternalErrorCode.CryptoOperationFailed,
			description: "Federation artifact algorithm policy could not be applied",
		});
	}
	const result = await new JwsService(scoped).verifyJwt(jwt, jwks, {
		typ: { expected: options.expectedTyp ?? JwtTyp.EntityStatement },
		keyId: "required",
	});
	return result as Result<ParsedEntityStatement>;
}

/** Decode a JWT entity statement without signature verification. */
export function decodeEntityStatement(
	jwt: string,
	options?: Pick<JwsServiceOptions, "maxCompactBytes">,
): Result<UnverifiedEntityStatement, FederationError> {
	try {
		const { header, payload } = decodeCompactJws(
			jwt,
			options?.maxCompactBytes === undefined ? undefined : { maxBytes: options.maxCompactBytes },
		);

		return ok({
			header: header as Record<string, unknown>,
			payload: payload as unknown as UnverifiedEntityStatement["payload"],
		} as UnverifiedEntityStatement);
	} catch (cause) {
		return err({
			code: "ERR_SIGNATURE_INVALID",
			description: cause instanceof Error ? cause.message : "Failed to decode JWT",
			cause,
		});
	}
}

/** Decode and schema-validate an Entity Configuration JWT without signature verification. */
export function decodeEntityConfiguration(
	jwt: string,
	options?: Pick<JwsServiceOptions, "maxCompactBytes">,
): Result<UnverifiedEntityStatement<EntityConfigurationPayload>, FederationError> {
	const decoded = decodeEntityStatement(jwt, options);
	if (!decoded.ok) return decoded;

	const typResult = requireEntityStatementTyp(decoded.value.header);
	if (!typResult.ok) return typResult;

	const parsed = EntityConfigurationSchema.safeParse(decoded.value.payload);
	if (!parsed.success) {
		return err({
			code: InternalErrorCode.TrustChainInvalid,
			description: `Invalid Entity Configuration payload: ${parsed.error.message}`,
			cause: parsed.error,
		});
	}

	return ok({
		header: decoded.value.header,
		payload: parsed.data,
	} as UnverifiedEntityStatement<EntityConfigurationPayload>);
}

/** Decode and schema-validate a Subordinate Statement JWT without signature verification. */
export function decodeSubordinateStatement(
	jwt: string,
	options?: Pick<JwsServiceOptions, "maxCompactBytes">,
): Result<UnverifiedEntityStatement<SubordinateStatementPayload>, FederationError> {
	const decoded = decodeEntityStatement(jwt, options);
	if (!decoded.ok) return decoded;

	const typResult = requireEntityStatementTyp(decoded.value.header);
	if (!typResult.ok) return typResult;

	const parsed = SubordinateStatementSchema.safeParse(decoded.value.payload);
	if (!parsed.success) {
		return err({
			code: InternalErrorCode.TrustChainInvalid,
			description: `Invalid Subordinate Statement payload: ${parsed.error.message}`,
			cause: parsed.error,
		});
	}

	return ok({
		header: decoded.value.header,
		payload: parsed.data,
	} as UnverifiedEntityStatement<SubordinateStatementPayload>);
}

function requireEntityStatementTyp(header: Record<string, unknown>): Result<void, FederationError> {
	if (header.typ !== JwtTyp.EntityStatement) {
		const actualTyp = String(header.typ);
		return err({
			code: InternalErrorCode.SignatureInvalid,
			description: `Invalid typ header: expected '${JwtTyp.EntityStatement}', got '${actualTyp}'`,
		});
	}

	return ok(undefined);
}

/** Assert that a JWT header has the expected `typ` value, throwing on mismatch. */
export function assertTypHeader(
	header: Record<string, unknown>,
	expectedTyp: string,
): asserts header is Record<string, unknown> & { typ: string } {
	if (header.typ !== expectedTyp) {
		throw new TypeError(`Expected typ '${expectedTyp}', got '${String(header.typ)}'`);
	}
}
