/** Stable builders for normal Entity Configuration and Subordinate Statement payloads. */
import {
	DEFAULT_ENTITY_STATEMENT_TTL_SECONDS,
	InternalErrorCode,
	JwtTyp,
	PolicyOperator,
	STANDARD_ENTITY_STATEMENT_CLAIMS,
	type SupportedAlgorithm,
} from "./constants.js";
import { err, type FederationError, federationError, ok, type Result } from "./errors.js";
import { signEntityStatement } from "./jose/sign.js";
import type { JwtSigner } from "./jose/signer.js";
import type { TrustChainConstraints } from "./schemas/constraints.js";
import {
	type EntityConfigurationPayload,
	EntityConfigurationSchema,
	type SubordinateStatementPayload,
	SubordinateStatementSchema,
} from "./schemas/entity-statement.js";
import type { JWKSet } from "./schemas/jwk.js";
import type { FederationMetadataPolicy } from "./schemas/metadata-policy.js";
import type { TrustMarkOwner, TrustMarkRef } from "./schemas/trust-mark.js";
import { type Clock, type EntityId, entityId, nowSeconds } from "./types.js";

export type EntityStatementKind = "entity-configuration" | "subordinate-statement";

export interface ValidateEntityStatementClaimsOptions {
	readonly kind: EntityStatementKind;
}

export type EntityStatementMetadata = Readonly<Record<string, Readonly<Record<string, unknown>>>>;

interface StatementTimeOptions {
	readonly clock?: Clock;
	readonly issuedAt?: number;
	readonly ttlSeconds?: number;
}

export interface BuildEntityConfigurationPayloadOptions extends StatementTimeOptions {
	readonly entityId: EntityId | string;
	readonly jwks: JWKSet;
	readonly metadata: EntityStatementMetadata;
	readonly authorityHints?: readonly (EntityId | string)[];
	readonly trustAnchorHints?: readonly (EntityId | string)[];
	readonly trustMarks?: readonly TrustMarkRef[];
	readonly trustMarkIssuers?: Readonly<Record<string, readonly (EntityId | string)[]>>;
	readonly trustMarkOwners?: Readonly<Record<string, TrustMarkOwner>>;
}

export interface BuildSubordinateStatementPayloadOptions extends StatementTimeOptions {
	readonly issuer: EntityId | string;
	readonly subject: EntityId | string;
	readonly jwks: JWKSet;
	readonly metadata?: EntityStatementMetadata;
	readonly metadataPolicy?: FederationMetadataPolicy | Readonly<Record<string, unknown>>;
	readonly constraints?: TrustChainConstraints;
	readonly sourceEndpoint?: string;
	readonly crit?: readonly string[];
	readonly metadataPolicyCrit?: readonly string[];
}

export interface SignEntityConfigurationOptions extends BuildEntityConfigurationPayloadOptions {
	readonly signer: JwtSigner;
	readonly alg?: SupportedAlgorithm;
}

export interface SignSubordinateStatementOptions extends BuildSubordinateStatementPayloadOptions {
	readonly signer: JwtSigner;
	readonly alg?: SupportedAlgorithm;
}

const STANDARD_METADATA_POLICY_OPERATORS: ReadonlySet<string> = new Set(
	Object.values(PolicyOperator),
);

const EC_ONLY_CLAIMS = [
	"authority_hints",
	"trust_anchor_hints",
	"trust_marks",
	"trust_mark_issuers",
	"trust_mark_owners",
] as const;

const SS_ONLY_CLAIMS = [
	"constraints",
	"metadata_policy",
	"metadata_policy_crit",
	"source_endpoint",
] as const;

const NORMAL_STATEMENT_FORBIDDEN_CLAIMS = ["aud", "trust_anchor"] as const;

export function buildEntityConfigurationPayload(
	options: BuildEntityConfigurationPayloadOptions,
): EntityConfigurationPayload {
	const eid = entityId(String(options.entityId));
	const { iat, exp } = resolveStatementTime(options);
	const payload: Record<string, unknown> = {
		iss: eid,
		sub: eid,
		iat,
		exp,
		jwks: options.jwks,
		metadata: options.metadata,
	};

	const authorityHints = copyEntityIdArray(options.authorityHints, "authority_hints");
	if (authorityHints) payload.authority_hints = authorityHints;

	const trustAnchorHints = copyEntityIdArray(options.trustAnchorHints, "trust_anchor_hints");
	if (trustAnchorHints) payload.trust_anchor_hints = trustAnchorHints;

	if (options.trustMarks && options.trustMarks.length > 0) {
		payload.trust_marks = [...options.trustMarks];
	}
	if (options.trustMarkIssuers) {
		payload.trust_mark_issuers = copyTrustMarkIssuers(options.trustMarkIssuers);
	}
	if (options.trustMarkOwners) {
		payload.trust_mark_owners = { ...options.trustMarkOwners };
	}

	assertValidEntityStatementClaims(payload, "entity-configuration");
	return payload as EntityConfigurationPayload;
}

export async function signEntityConfiguration(
	options: SignEntityConfigurationOptions,
): Promise<string> {
	const payload = buildEntityConfigurationPayload(options);
	return signEntityStatement(payload as Record<string, unknown>, options.signer, {
		typ: JwtTyp.EntityStatement,
		...(options.alg ? { alg: options.alg } : {}),
	});
}

export function buildSubordinateStatementPayload(
	options: BuildSubordinateStatementPayloadOptions,
): SubordinateStatementPayload {
	const issuer = entityId(String(options.issuer));
	const subject = entityId(String(options.subject));
	const { iat, exp } = resolveStatementTime(options);
	const payload: Record<string, unknown> = {
		iss: issuer,
		sub: subject,
		iat,
		exp,
		jwks: options.jwks,
	};

	if (options.metadata !== undefined) payload.metadata = options.metadata;
	if (options.metadataPolicy !== undefined) payload.metadata_policy = options.metadataPolicy;
	if (options.constraints !== undefined) payload.constraints = options.constraints;
	if (options.sourceEndpoint !== undefined) payload.source_endpoint = options.sourceEndpoint;
	if (options.crit && options.crit.length > 0) payload.crit = [...options.crit];
	if (options.metadataPolicyCrit && options.metadataPolicyCrit.length > 0) {
		payload.metadata_policy_crit = [...options.metadataPolicyCrit];
	}

	assertValidEntityStatementClaims(payload, "subordinate-statement");
	return payload as SubordinateStatementPayload;
}

export async function signSubordinateStatement(
	options: SignSubordinateStatementOptions,
): Promise<string> {
	const payload = buildSubordinateStatementPayload(options);
	return signEntityStatement(payload as Record<string, unknown>, options.signer, {
		typ: JwtTyp.EntityStatement,
		...(options.alg ? { alg: options.alg } : {}),
	});
}

export function validateEntityStatementClaims(
	payload: Readonly<Record<string, unknown>>,
	options: ValidateEntityStatementClaimsOptions,
): Result<void, FederationError> {
	const errors: string[] = [];
	const schema =
		options.kind === "entity-configuration"
			? EntityConfigurationSchema
			: SubordinateStatementSchema;
	const schemaResult = schema.safeParse(payload);
	if (!schemaResult.success) {
		for (const issue of schemaResult.error.issues) {
			const path = issue.path.length > 0 ? issue.path.map(String).join(".") : "payload";
			errors.push(`${path}: ${issue.message}`);
		}
	}

	if (options.kind === "entity-configuration") {
		forbidClaims(payload, SS_ONLY_CLAIMS, errors, "Entity Configuration");
	} else {
		forbidClaims(payload, EC_ONLY_CLAIMS, errors, "Subordinate Statement");
	}
	forbidClaims(payload, NORMAL_STATEMENT_FORBIDDEN_CLAIMS, errors, "normal Entity Statement");

	validateCrit(payload, errors);
	validateMetadataPolicyCrit(payload, errors);
	validateMetadataPolicyShape(payload, errors);
	validateMetadataValues(payload.metadata, errors);
	validateTrustMarkIssuers(payload.trust_mark_issuers, errors);

	if (errors.length > 0) {
		return err(
			federationError(
				InternalErrorCode.TrustChainInvalid,
				`Invalid Entity Statement claims: ${errors.join("; ")}`,
			),
		);
	}

	return ok(undefined);
}

function assertValidEntityStatementClaims(
	payload: Readonly<Record<string, unknown>>,
	kind: EntityStatementKind,
): void {
	const result = validateEntityStatementClaims(payload, { kind });
	if (!result.ok) {
		throw new Error(result.error.description);
	}
}

function resolveStatementTime(options: StatementTimeOptions): { iat: number; exp: number } {
	const iat = options.issuedAt ?? nowSeconds(options.clock);
	const ttlSeconds = options.ttlSeconds ?? DEFAULT_ENTITY_STATEMENT_TTL_SECONDS;
	if (!Number.isSafeInteger(iat) || iat <= 0) {
		throw new TypeError("issuedAt must be a positive safe integer NumericDate");
	}
	if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds <= 0) {
		throw new TypeError("ttlSeconds must be a positive safe integer");
	}
	const exp = iat + ttlSeconds;
	if (!Number.isSafeInteger(exp) || exp <= iat) {
		throw new TypeError("expiration must be after issued-at");
	}
	return { iat, exp };
}

function copyEntityIdArray(
	values: readonly (EntityId | string)[] | undefined,
	field: string,
): string[] | undefined {
	if (values === undefined) return undefined;
	if (values.length === 0) {
		throw new TypeError(`${field} must not be empty`);
	}
	return values.map((value) => entityId(String(value)));
}

function copyTrustMarkIssuers(
	issuers: Readonly<Record<string, readonly (EntityId | string)[]>>,
): Record<string, string[]> {
	const result: Record<string, string[]> = {};
	for (const [trustMarkType, values] of Object.entries(issuers)) {
		result[trustMarkType] = values.map((value) => entityId(String(value)));
	}
	return result;
}

function forbidClaims(
	payload: Readonly<Record<string, unknown>>,
	claims: readonly string[],
	errors: string[],
	kind: string,
) {
	for (const claim of claims) {
		if (payload[claim] !== undefined) {
			errors.push(`${kind} cannot contain '${claim}'`);
		}
	}
}

function validateCrit(payload: Readonly<Record<string, unknown>>, errors: string[]) {
	if (payload.crit === undefined) return;
	const crit = payload.crit;
	if (!Array.isArray(crit)) {
		errors.push("crit must be an array of strings");
		return;
	}
	if (crit.length === 0) {
		errors.push("crit must not be empty");
		return;
	}
	const seen = new Set<string>();
	for (const claim of crit) {
		if (typeof claim !== "string") {
			errors.push("crit entries must be strings");
			continue;
		}
		if (seen.has(claim)) {
			errors.push(`crit contains duplicate claim '${claim}'`);
			continue;
		}
		seen.add(claim);
		if (STANDARD_ENTITY_STATEMENT_CLAIMS.has(claim)) {
			errors.push(`crit cannot list standard Entity Statement claim '${claim}'`);
			continue;
		}
		if (payload[claim] === undefined) {
			errors.push(`crit references missing claim '${claim}'`);
		}
	}
}

function validateMetadataPolicyCrit(payload: Readonly<Record<string, unknown>>, errors: string[]) {
	if (payload.metadata_policy_crit === undefined) return;
	const crit = payload.metadata_policy_crit;
	if (!Array.isArray(crit)) {
		errors.push("metadata_policy_crit must be an array of strings");
		return;
	}
	if (crit.length === 0) {
		errors.push("metadata_policy_crit must not be empty");
		return;
	}
	const seen = new Set<string>();
	for (const operator of crit) {
		if (typeof operator !== "string") {
			errors.push("metadata_policy_crit entries must be strings");
			continue;
		}
		if (seen.has(operator)) {
			errors.push(`metadata_policy_crit contains duplicate operator '${operator}'`);
			continue;
		}
		seen.add(operator);
		if (STANDARD_METADATA_POLICY_OPERATORS.has(operator)) {
			errors.push(`metadata_policy_crit cannot list standard operator '${operator}'`);
		}
	}
}

function validateMetadataPolicyShape(payload: Readonly<Record<string, unknown>>, errors: string[]) {
	if (payload.metadata_policy === undefined) return;
	if (!isJsonObject(payload.metadata_policy)) {
		errors.push("metadata_policy must be a JSON object");
		return;
	}
	for (const [entityType, parameterPolicies] of Object.entries(payload.metadata_policy)) {
		if (!isJsonObject(parameterPolicies)) {
			errors.push(`metadata_policy.${entityType} must be a JSON object`);
			continue;
		}
		for (const [parameter, operatorPolicy] of Object.entries(parameterPolicies)) {
			if (!isJsonObject(operatorPolicy)) {
				errors.push(`metadata_policy.${entityType}.${parameter} must be a JSON object`);
			}
		}
	}
}

function validateMetadataValues(value: unknown, errors: string[], path = "metadata") {
	if (value === undefined) return;
	if (!isJsonObject(value)) {
		errors.push(`${path} must be a JSON object`);
		return;
	}
	for (const [key, child] of Object.entries(value)) {
		const childPath = `${path}.${key}`;
		if (child === null) {
			errors.push(`${childPath} must not be null`);
			continue;
		}
		if (Array.isArray(child)) {
			validateArrayMetadataValues(child, errors, childPath);
			continue;
		}
		if (isJsonObject(child)) {
			validateMetadataValues(child, errors, childPath);
		} else if (path === "metadata") {
			errors.push(`${childPath} must be a JSON object`);
		}
	}
}

function validateArrayMetadataValues(values: readonly unknown[], errors: string[], path: string) {
	for (let i = 0; i < values.length; i++) {
		const child = values[i];
		const childPath = `${path}.${i}`;
		if (child === null) {
			errors.push(`${childPath} must not be null`);
		} else if (Array.isArray(child)) {
			validateArrayMetadataValues(child, errors, childPath);
		} else if (isJsonObject(child)) {
			validateMetadataValues(child, errors, childPath);
		}
	}
}

function validateTrustMarkIssuers(value: unknown, errors: string[]) {
	if (value === undefined) return;
	if (!isJsonObject(value)) {
		errors.push("trust_mark_issuers must be a JSON object");
		return;
	}
	for (const [trustMarkType, issuers] of Object.entries(value)) {
		if (!Array.isArray(issuers)) {
			errors.push(`trust_mark_issuers.${trustMarkType} must be an array`);
			continue;
		}
		for (const issuer of issuers) {
			if (typeof issuer !== "string") {
				errors.push(`trust_mark_issuers.${trustMarkType} entries must be strings`);
			} else {
				try {
					entityId(issuer);
				} catch {
					errors.push(`trust_mark_issuers.${trustMarkType} entries must be Entity Identifiers`);
				}
			}
		}
	}
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
	return !!value && typeof value === "object" && !Array.isArray(value);
}
