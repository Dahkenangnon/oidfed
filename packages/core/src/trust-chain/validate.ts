/** Trust chain validation: verifies signatures, expiry, issuer-subject chaining, and metadata policy along the chain. */
import {
	DEFAULT_CLOCK_SKEW_SECONDS,
	InternalErrorCode,
	JwtTyp,
	PolicyOperator,
	STANDARD_ENTITY_STATEMENT_CLAIMS,
	SUPPORTED_ALGORITHMS,
} from "../constants.js";
import { applyAllowedEntityTypes, checkConstraints } from "../constraints/index.js";
import { decodeEntityStatement, verifyEntityStatement } from "../jose/verify.js";
import { validateJwkSetUseRequirement } from "../jwks/use-requirement.js";
import { applyMetadataPolicy } from "../metadata-policy/apply.js";
import { resolveMetadataPolicy } from "../metadata-policy/merge.js";
import {
	EntityConfigurationSchema,
	SubordinateStatementSchema,
} from "../schemas/entity-statement.js";
import type { JWK, JWKSet } from "../schemas/jwk.js";
import type { FederationMetadata } from "../schemas/metadata.js";
import { validateTrustMark } from "../trust-marks/index.js";
import {
	type ChainSelectionStrategy,
	type Clock,
	type EntityId,
	type FederationOptions,
	nowSeconds,
	type ParsedEntityStatement,
	type TrustAnchorSet,
	type ValidatedTrustChain,
	type ValidatedTrustMark,
	type ValidationError,
	type ValidationResult,
} from "../types.js";

const defaultClock: Clock = {
	now: () => nowSeconds(),
};

const STANDARD_METADATA_POLICY_OPERATORS: ReadonlySet<string> = new Set(
	Object.values(PolicyOperator),
);

/** Calculate the earliest expiration across all statements in a chain. */
export function calculateChainExpiration(chain: ParsedEntityStatement[]): number {
	return Math.min(...chain.map((es) => es.payload.exp));
}

function addError(
	errors: ValidationError[],
	code: string,
	message: string,
	opts?: { statementIndex?: number; field?: string; checkNumber?: number },
) {
	errors.push({
		code: code as ValidationError["code"],
		message,
		...(opts?.statementIndex !== undefined ? { statementIndex: opts.statementIndex } : {}),
		...(opts?.field !== undefined ? { field: opts.field } : {}),
		...(opts?.checkNumber !== undefined ? { checkNumber: opts.checkNumber } : {}),
	});
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
	return !!value && typeof value === "object" && !Array.isArray(value);
}

function addSchemaIssues(
	errors: ValidationError[],
	issues: ReadonlyArray<{ path: readonly PropertyKey[]; message: string }>,
	statementIndex: number,
	defaultField: string,
) {
	for (const issue of issues) {
		const field = issue.path[0] ? String(issue.path[0]) : defaultField;
		const path = issue.path.length > 0 ? issue.path.map(String).join(".") : defaultField;
		addError(
			errors,
			InternalErrorCode.TrustChainInvalid,
			`Invalid ${path} at statement ${statementIndex}: ${issue.message}`,
			{ statementIndex, field, checkNumber: 1 },
		);
	}
}

function addMetadataNullErrors(
	errors: ValidationError[],
	value: unknown,
	statementIndex: number,
	path: string,
) {
	if (value === null) {
		addError(
			errors,
			InternalErrorCode.TrustChainInvalid,
			`Metadata value '${path}' MUST NOT be null at statement ${statementIndex}`,
			{ statementIndex, field: "metadata", checkNumber: 16 },
		);
		return;
	}
	if (Array.isArray(value)) {
		for (let i = 0; i < value.length; i++) {
			addMetadataNullErrors(errors, value[i], statementIndex, `${path}.${i}`);
		}
		return;
	}
	if (isJsonObject(value)) {
		for (const [key, child] of Object.entries(value)) {
			addMetadataNullErrors(errors, child, statementIndex, `${path}.${key}`);
		}
	}
}

function validateMetadataPolicyShape(
	errors: ValidationError[],
	policy: unknown,
	statementIndex: number,
) {
	if (policy === undefined) {
		return;
	}
	if (!isJsonObject(policy)) {
		addError(
			errors,
			InternalErrorCode.TrustChainInvalid,
			`metadata_policy MUST be a JSON object at statement ${statementIndex}`,
			{ statementIndex, field: "metadata_policy", checkNumber: 19 },
		);
		return;
	}
	for (const [entityType, parameterPolicies] of Object.entries(policy)) {
		if (!isJsonObject(parameterPolicies)) {
			addError(
				errors,
				InternalErrorCode.TrustChainInvalid,
				`metadata_policy.${entityType} MUST be a JSON object at statement ${statementIndex}`,
				{ statementIndex, field: "metadata_policy", checkNumber: 19 },
			);
			continue;
		}
		for (const [parameter, operatorPolicy] of Object.entries(parameterPolicies)) {
			if (!isJsonObject(operatorPolicy)) {
				addError(
					errors,
					InternalErrorCode.TrustChainInvalid,
					`metadata_policy.${entityType}.${parameter} MUST be a JSON object at statement ${statementIndex}`,
					{ statementIndex, field: "metadata_policy", checkNumber: 19 },
				);
			}
		}
	}
}

function validateTrustMarkReferenceSyntax(
	errors: ValidationError[],
	trustMarks: unknown,
	statementIndex: number,
) {
	if (!Array.isArray(trustMarks)) {
		return;
	}
	for (let i = 0; i < trustMarks.length; i++) {
		const trustMarkRef = trustMarks[i];
		if (!isJsonObject(trustMarkRef)) {
			continue;
		}
		const trustMarkType = trustMarkRef.trust_mark_type;
		const trustMarkJwt = trustMarkRef.trust_mark;
		if (typeof trustMarkType !== "string" || typeof trustMarkJwt !== "string") {
			continue;
		}

		const decoded = decodeEntityStatement(trustMarkJwt);
		if (!decoded.ok) {
			addError(
				errors,
				InternalErrorCode.TrustChainInvalid,
				`Invalid trust_marks entry at statement ${statementIndex}: trust_mark is not a signed JWT`,
				{ statementIndex, field: "trust_marks", checkNumber: 16 },
			);
			continue;
		}
		const embeddedTrustMarkType = (decoded.value.payload as Record<string, unknown>)
			.trust_mark_type;
		if (embeddedTrustMarkType !== trustMarkType) {
			addError(
				errors,
				InternalErrorCode.TrustChainInvalid,
				`Invalid trust_marks entry at statement ${statementIndex}: trust_mark_type does not match embedded Trust Mark`,
				{ statementIndex, field: "trust_marks", checkNumber: 16 },
			);
		}
	}
}

function validateRawStatementShape(
	errors: ValidationError[],
	statement: ParsedEntityStatement,
	statementIndex: number,
	lastIndex: number,
) {
	const payload = statement.payload as Record<string, unknown>;
	const isSubjectEc = statementIndex === 0;
	const isTrailingTrustAnchorEc = statementIndex === lastIndex && payload.iss === payload.sub;
	const schema =
		isSubjectEc || isTrailingTrustAnchorEc ? EntityConfigurationSchema : SubordinateStatementSchema;
	const schemaResult = schema.safeParse(payload);
	if (!schemaResult.success) {
		addSchemaIssues(errors, schemaResult.error.issues, statementIndex, "payload");
	}

	if (payload.metadata !== undefined) {
		if (!isJsonObject(payload.metadata)) {
			addError(
				errors,
				InternalErrorCode.TrustChainInvalid,
				`metadata MUST be a JSON object at statement ${statementIndex}`,
				{ statementIndex, field: "metadata", checkNumber: 16 },
			);
		} else {
			for (const [entityType, metadata] of Object.entries(payload.metadata)) {
				if (!isJsonObject(metadata)) {
					addError(
						errors,
						InternalErrorCode.TrustChainInvalid,
						`metadata.${entityType} MUST be a JSON object at statement ${statementIndex}`,
						{ statementIndex, field: "metadata", checkNumber: 16 },
					);
				} else {
					addMetadataNullErrors(errors, metadata, statementIndex, `metadata.${entityType}`);
				}
			}
		}
	}

	validateMetadataPolicyShape(errors, payload.metadata_policy, statementIndex);
	validateTrustMarkReferenceSyntax(errors, payload.trust_marks, statementIndex);

	const metadataPolicyCrit = payload.metadata_policy_crit;
	if (Array.isArray(metadataPolicyCrit)) {
		for (const operator of metadataPolicyCrit) {
			if (typeof operator === "string" && STANDARD_METADATA_POLICY_OPERATORS.has(operator)) {
				addError(
					errors,
					InternalErrorCode.TrustChainInvalid,
					`metadata_policy_crit MUST NOT list standard operator '${operator}' at statement ${statementIndex}`,
					{ statementIndex, field: "metadata_policy_crit", checkNumber: 19 },
				);
			}
		}
	}
}

/** Validate a raw trust chain (array of JWTs) against a set of trust anchors, returning resolved metadata. */
export async function validateTrustChain(
	chain: ReadonlyArray<string>,
	trustAnchors: TrustAnchorSet,
	options?: FederationOptions & {
		verboseErrors?: boolean;
		explicitRegistrationAudience?: EntityId | string;
	},
): Promise<ValidationResult> {
	const errors: ValidationError[] = [];
	const clockSkew = options?.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;
	const nowSeconds = options?.clock ? options.clock.now() : defaultClock.now();
	const verifyOptions = {
		clockSkewSeconds: clockSkew,
		...(options?.clock ? { clock: options.clock } : {}),
	};

	if (chain.length === 0) {
		addError(errors, InternalErrorCode.TrustChainInvalid, "Trust chain MUST NOT be empty", {
			checkNumber: 1,
		});
		return { valid: false, errors };
	}

	const parsed: ParsedEntityStatement[] = [];
	for (let j = 0; j < chain.length; j++) {
		const decodeResult = decodeEntityStatement(chain[j] as string);
		if (!decodeResult.ok) {
			addError(
				errors,
				InternalErrorCode.TrustChainInvalid,
				`Failed to decode statement at index ${j}: ${decodeResult.error.description}`,
				{
					statementIndex: j,
					checkNumber: 1,
				},
			);
			return { valid: false, errors };
		}
		parsed.push(decodeResult.value);
	}

	const lastStatementIndex = parsed.length - 1;
	for (let j = 0; j < parsed.length; j++) {
		const es = parsed[j] as ParsedEntityStatement;
		const p = es.payload as Record<string, unknown>;
		const h = es.header;

		validateRawStatementShape(errors, es, j, lastStatementIndex);

		if (!p.iss)
			addError(errors, InternalErrorCode.TrustChainInvalid, `Missing 'iss' at statement ${j}`, {
				statementIndex: j,
				field: "iss",
				checkNumber: 1,
			});
		if (!p.sub)
			addError(errors, InternalErrorCode.TrustChainInvalid, `Missing 'sub' at statement ${j}`, {
				statementIndex: j,
				field: "sub",
				checkNumber: 1,
			});
		if (!p.iat)
			addError(errors, InternalErrorCode.TrustChainInvalid, `Missing 'iat' at statement ${j}`, {
				statementIndex: j,
				field: "iat",
				checkNumber: 1,
			});
		if (!p.exp)
			addError(errors, InternalErrorCode.TrustChainInvalid, `Missing 'exp' at statement ${j}`, {
				statementIndex: j,
				field: "exp",
				checkNumber: 1,
			});

		if (typeof p.iat === "number") {
			if (!Number.isSafeInteger(p.iat)) {
				addError(
					errors,
					InternalErrorCode.TrustChainInvalid,
					`'iat' is not a safe integer at statement ${j}`,
					{ statementIndex: j, field: "iat", checkNumber: 4 },
				);
			} else if (p.iat > nowSeconds + clockSkew) {
				addError(
					errors,
					InternalErrorCode.TrustChainInvalid,
					`'iat' is in the future at statement ${j}`,
					{ statementIndex: j, field: "iat", checkNumber: 4 },
				);
			}
		}

		if (typeof p.exp === "number") {
			if (!Number.isSafeInteger(p.exp)) {
				addError(
					errors,
					InternalErrorCode.TrustChainInvalid,
					`'exp' is not a safe integer at statement ${j}`,
					{ statementIndex: j, field: "exp", checkNumber: 5 },
				);
			} else if (p.exp < nowSeconds - clockSkew) {
				addError(errors, InternalErrorCode.Expired, `Statement at index ${j} has expired`, {
					statementIndex: j,
					field: "exp",
					checkNumber: 5,
				});
			}
		}

		if (h.typ !== JwtTyp.EntityStatement) {
			addError(
				errors,
				InternalErrorCode.TrustChainInvalid,
				`Invalid typ header at statement ${j}: '${String(h.typ)}'`,
				{ statementIndex: j, field: "typ", checkNumber: 7 },
			);
		}

		const alg = h.alg as string | undefined;
		if (!alg || alg === "none" || !(SUPPORTED_ALGORITHMS as readonly string[]).includes(alg)) {
			addError(
				errors,
				InternalErrorCode.UnsupportedAlg,
				`Unsupported algorithm at statement ${j}: '${String(alg)}'`,
				{ statementIndex: j, field: "alg", checkNumber: 7 },
			);
		}

		if (!p.jwks) {
			addError(errors, InternalErrorCode.TrustChainInvalid, `Missing 'jwks' at statement ${j}`, {
				statementIndex: j,
				field: "jwks",
				checkNumber: 9,
			});
		}

		if (p.metadata && typeof p.metadata === "object") {
			for (const [entityType, metaObj] of Object.entries(p.metadata as Record<string, unknown>)) {
				if (metaObj && typeof metaObj === "object") {
					for (const [key, val] of Object.entries(metaObj as Record<string, unknown>)) {
						if (val === null) {
							addError(
								errors,
								InternalErrorCode.TrustChainInvalid,
								`Metadata value '${entityType}.${key}' MUST NOT be null at statement ${j}`,
								{ statementIndex: j, field: "metadata", checkNumber: 16 },
							);
						}
					}
				}
			}
		}

		// JWK Set params MUST NOT appear in federation_entity metadata
		if (p.metadata && typeof p.metadata === "object") {
			const meta = p.metadata as Record<string, Record<string, unknown>>;
			const fedEntity = meta.federation_entity;
			if (fedEntity && typeof fedEntity === "object") {
				for (const forbidden of ["jwks", "jwks_uri", "signed_jwks_uri"] as const) {
					if (forbidden in fedEntity) {
						addError(
							errors,
							InternalErrorCode.TrustChainInvalid,
							`'${forbidden}' MUST NOT be used in federation_entity metadata at statement ${j}`,
							{ statementIndex: j, field: "metadata", checkNumber: 16 },
						);
					}
				}
			}

			// openid_provider.issuer MUST match entity identifier
			const subjectEntityId = p.sub as string;
			const op = meta.openid_provider;
			if (op && typeof op === "object" && "issuer" in op && op.issuer !== subjectEntityId) {
				addError(
					errors,
					InternalErrorCode.TrustChainInvalid,
					`openid_provider.issuer '${String(op.issuer)}' MUST match entity identifier '${subjectEntityId}' at statement ${j}`,
					{ statementIndex: j, field: "metadata", checkNumber: 16 },
				);
			}

			// oauth_authorization_server.issuer MUST match entity identifier
			const oas = meta.oauth_authorization_server;
			if (oas && typeof oas === "object" && "issuer" in oas && oas.issuer !== subjectEntityId) {
				addError(
					errors,
					InternalErrorCode.TrustChainInvalid,
					`oauth_authorization_server.issuer '${String(oas.issuer)}' MUST match entity identifier '${subjectEntityId}' at statement ${j}`,
					{ statementIndex: j, field: "metadata", checkNumber: 16 },
				);
			}

			// Inline `jwks` per entity type: enforce the conditional `use` REQUIRED rule.
			// Skips federation_entity (jwks already rejected there above).
			for (const [entityType, metaObj] of Object.entries(meta)) {
				if (entityType === "federation_entity") continue;
				if (!metaObj || typeof metaObj !== "object") continue;
				const jwks = (metaObj as { jwks?: unknown }).jwks;
				if (!jwks || typeof jwks !== "object") continue;
				const keys = (jwks as { keys?: unknown }).keys;
				if (!Array.isArray(keys)) continue;
				const useResult = validateJwkSetUseRequirement(keys as JWK[]);
				if (!useResult.ok) {
					addError(errors, InternalErrorCode.TrustChainInvalid, useResult.error.description, {
						statementIndex: j,
						field: "metadata",
						checkNumber: 16,
					});
				}
			}
		}

		const critClaims = p.crit as string[] | undefined;
		if (Array.isArray(critClaims)) {
			const understood = options?.understoodCriticalClaims ?? new Set<string>();

			const critSet = new Set<string>();
			for (const claim of critClaims) {
				if (critSet.has(claim)) {
					addError(
						errors,
						InternalErrorCode.TrustChainInvalid,
						`Duplicate claim '${claim}' in crit at statement ${j}`,
						{ statementIndex: j, field: "crit", checkNumber: 13 },
					);
				}
				critSet.add(claim);
			}

			for (const claim of critClaims) {
				if (STANDARD_ENTITY_STATEMENT_CLAIMS.has(claim)) {
					addError(
						errors,
						InternalErrorCode.TrustChainInvalid,
						`Standard claim '${claim}' MUST NOT appear in crit at statement ${j}`,
						{ statementIndex: j, field: "crit", checkNumber: 13 },
					);
				} else if (!understood.has(claim)) {
					addError(
						errors,
						InternalErrorCode.TrustChainInvalid,
						`Unknown critical claim '${claim}' at statement ${j}`,
						{ statementIndex: j, field: "crit", checkNumber: 13 },
					);
				}

				if (!(claim in p)) {
					addError(
						errors,
						InternalErrorCode.TrustChainInvalid,
						`Claim '${claim}' listed in crit does not exist in JWT payload at statement ${j}`,
						{ statementIndex: j, field: "crit", checkNumber: 13 },
					);
				}
			}
		}

		const isEC = p.iss === p.sub;
		const ecOnlyClaims = [
			"authority_hints",
			"trust_anchor_hints",
			"trust_marks",
			"trust_mark_issuers",
			"trust_mark_owners",
		] as const;
		const ssOnlyClaims = [
			"metadata_policy",
			"metadata_policy_crit",
			"constraints",
			"source_endpoint",
		] as const;

		for (const claim of ecOnlyClaims) {
			if (p[claim] !== undefined && !isEC) {
				addError(
					errors,
					InternalErrorCode.TrustChainInvalid,
					`'${claim}' MUST only appear in Entity Configurations (iss===sub) at statement ${j}`,
					{ statementIndex: j, field: claim, checkNumber: 14 },
				);
			}
		}
		for (const claim of ssOnlyClaims) {
			if (p[claim] !== undefined && isEC) {
				addError(
					errors,
					InternalErrorCode.TrustChainInvalid,
					`'${claim}' MUST only appear in Subordinate Statements at statement ${j}`,
					{ statementIndex: j, field: claim, checkNumber: 17 },
				);
			}
		}

		const authorityHints = p.authority_hints as string[] | undefined;
		if (Array.isArray(authorityHints) && authorityHints.length === 0) {
			addError(
				errors,
				InternalErrorCode.TrustChainInvalid,
				`'authority_hints' MUST NOT be empty array at statement ${j}`,
				{ statementIndex: j, field: "authority_hints", checkNumber: 14 },
			);
		}

		const allowedExplicitRegistrationAudience =
			j === 0 &&
			options?.explicitRegistrationAudience !== undefined &&
			p.aud === options.explicitRegistrationAudience;
		if (p.aud !== undefined && !allowedExplicitRegistrationAudience) {
			addError(
				errors,
				InternalErrorCode.TrustChainInvalid,
				`'aud' MUST NOT appear in non-registration entity statements at statement ${j}`,
				{ statementIndex: j, field: "aud", checkNumber: 26 },
			);
		}
		if (p.trust_anchor !== undefined) {
			addError(
				errors,
				InternalErrorCode.TrustChainInvalid,
				`'trust_anchor' MUST NOT appear in non-registration entity statements at statement ${j}`,
				{ statementIndex: j, field: "trust_anchor", checkNumber: 27 },
			);
		}

		if ((h as Record<string, unknown>).trust_chain !== undefined) {
			addError(
				errors,
				InternalErrorCode.TrustChainInvalid,
				`Entity Statements MUST NOT contain trust_chain header at statement ${j}`,
				{ statementIndex: j, field: "trust_chain", checkNumber: 24 },
			);
		}
		if ((h as Record<string, unknown>).peer_trust_chain !== undefined) {
			addError(
				errors,
				InternalErrorCode.TrustChainInvalid,
				`Entity Statements MUST NOT contain peer_trust_chain header at statement ${j}`,
				{ statementIndex: j, field: "peer_trust_chain", checkNumber: 25 },
			);
		}

		if (!h.kid || typeof h.kid !== "string") {
			addError(
				errors,
				InternalErrorCode.TrustChainInvalid,
				`Missing or invalid 'kid' header at statement ${j}`,
				{ statementIndex: j, field: "kid", checkNumber: 8 },
			);
		}
	}

	if (errors.length > 0) {
		if (options?.verboseErrors) {
			return { valid: false, errors };
		}
		return {
			valid: false,
			errors: [
				{
					code: InternalErrorCode.TrustChainInvalid,
					message: "Trust chain validation failed",
				},
			],
		};
	}

	const leaf = parsed[0] as ParsedEntityStatement;
	const leafPayload = leaf.payload as Record<string, unknown>;

	if (leafPayload.iss !== leafPayload.sub) {
		addError(errors, InternalErrorCode.TrustChainInvalid, `Leaf EC iss !== sub`, {
			statementIndex: 0,
			checkNumber: 9,
		});
	}

	if (leaf.payload.jwks) {
		const selfVerify = await verifyEntityStatement(
			chain[0] as string,
			leaf.payload.jwks,
			verifyOptions,
		);
		if (!selfVerify.ok) {
			addError(
				errors,
				InternalErrorCode.SignatureInvalid,
				`Leaf EC self-signature invalid: ${selfVerify.error.description}`,
				{ statementIndex: 0, checkNumber: 10 },
			);
		}
	} else {
		addError(
			errors,
			InternalErrorCode.TrustChainInvalid,
			`Leaf EC missing jwks for self-verification`,
			{ statementIndex: 0, checkNumber: 10 },
		);
	}

	for (let j = 0; j < parsed.length - 1; j++) {
		const current = parsed[j] as ParsedEntityStatement;
		const next = parsed[j + 1] as ParsedEntityStatement;

		const currentIss = (current.payload as Record<string, unknown>).iss as string;
		const nextSub = (next.payload as Record<string, unknown>).sub as string;
		if (currentIss !== nextSub) {
			addError(
				errors,
				InternalErrorCode.TrustChainInvalid,
				`Chain continuity broken at statement ${j}: iss '${currentIss}' !== next sub '${nextSub}'`,
				{ statementIndex: j, checkNumber: 12 },
			);
		}

		if (next.payload.jwks) {
			const sigResult = await verifyEntityStatement(
				chain[j] as string,
				next.payload.jwks,
				verifyOptions,
			);
			if (!sigResult.ok) {
				addError(
					errors,
					InternalErrorCode.SignatureInvalid,
					`Signature invalid at statement ${j}: ${sigResult.error.description}`,
					{ statementIndex: j, checkNumber: 13 },
				);
			}
		}
	}

	const lastIdx = parsed.length - 1;
	const last = parsed[lastIdx] as ParsedEntityStatement;
	const lastPayload = last.payload as Record<string, unknown>;
	const lastIss = lastPayload.iss as string;
	const hasTrailingTrustAnchorEc = lastPayload.iss === lastPayload.sub;

	if (!trustAnchors.has(lastIss as EntityId)) {
		addError(
			errors,
			InternalErrorCode.TrustAnchorUnknown,
			`Trust anchor '${lastIss}' is not in configured trust anchors`,
			{ statementIndex: lastIdx, checkNumber: 14 },
		);
	}

	const taConfig = trustAnchors.get(lastIss as EntityId);
	if (taConfig) {
		const taVerify = await verifyEntityStatement(
			chain[lastIdx] as string,
			taConfig.jwks,
			verifyOptions,
		);
		if (!taVerify.ok) {
			addError(
				errors,
				InternalErrorCode.SignatureInvalid,
				`TA signature verification failed: ${taVerify.error.description}`,
				{ statementIndex: lastIdx, checkNumber: 15 },
			);
		}
	}

	// TA EC MUST NOT have authority_hints or trust_anchor_hints
	if (hasTrailingTrustAnchorEc && trustAnchors.has(lastIss as EntityId)) {
		if (lastPayload.authority_hints !== undefined) {
			addError(
				errors,
				InternalErrorCode.TrustChainInvalid,
				`Trust Anchor EC MUST NOT contain authority_hints`,
				{ statementIndex: lastIdx, field: "authority_hints", checkNumber: 14 },
			);
		}
		if (lastPayload.trust_anchor_hints !== undefined) {
			addError(
				errors,
				InternalErrorCode.TrustChainInvalid,
				`Trust Anchor EC MUST NOT contain trust_anchor_hints`,
				{ statementIndex: lastIdx, field: "trust_anchor_hints", checkNumber: 15 },
			);
		}
	}

	// Non-TA Entity Configurations MUST have authority_hints
	for (let j = 0; j < parsed.length; j++) {
		const stmt = parsed[j] as ParsedEntityStatement;
		const sp = stmt.payload as Record<string, unknown>;
		const isEC = sp.iss === sp.sub;
		const isTrustAnchor = j === lastIdx && trustAnchors.has(sp.iss as EntityId);
		if (isEC && !isTrustAnchor && sp.authority_hints === undefined) {
			addError(
				errors,
				InternalErrorCode.TrustChainInvalid,
				`Entity Configuration at statement ${j} MUST contain authority_hints (non-TA entity)`,
				{ statementIndex: j, field: "authority_hints", checkNumber: 14 },
			);
		}
	}

	// For each SS, verify iss appears in subject's authority_hints
	for (let j = 1; j < parsed.length; j++) {
		const ss = parsed[j] as ParsedEntityStatement;
		const ssPayload = ss.payload as Record<string, unknown>;
		if (ssPayload.iss === ssPayload.sub) continue;
		const subject = parsed[j - 1] as ParsedEntityStatement;
		const subjectPayload = subject.payload as Record<string, unknown>;
		const subjectHints = subjectPayload.authority_hints as string[] | undefined;
		if (subjectPayload.iss === subjectPayload.sub && subjectHints) {
			if (!subjectHints.includes(ssPayload.iss as string)) {
				addError(
					errors,
					InternalErrorCode.TrustChainInvalid,
					`SS issuer '${ssPayload.iss}' not found in subject's authority_hints at statement ${j}`,
					{ statementIndex: j, field: "authority_hints", checkNumber: 6 },
				);
			}
		}
	}

	if (errors.length > 0) {
		if (options?.verboseErrors) {
			return { valid: false, errors };
		}
		return {
			valid: false,
			errors: [
				{
					code: InternalErrorCode.TrustChainInvalid,
					message: "Trust chain validation failed",
				},
			],
		};
	}

	const subordinateStatements = hasTrailingTrustAnchorEc ? parsed.slice(1, -1) : parsed.slice(1);

	let metadata = (leafPayload.metadata ?? {}) as Record<string, Record<string, unknown>>;

	// Merge Immediate Superior's SS metadata before applying allowed_entity_types constraints,
	// so the filter sees the fully merged metadata as required by the spec.
	if (subordinateStatements.length > 0) {
		const immSupMeta = (subordinateStatements[0]?.payload as Record<string, unknown>).metadata as
			| Record<string, Record<string, unknown>>
			| undefined;
		if (immSupMeta) {
			for (const [entityType, params] of Object.entries(immSupMeta)) {
				const existingMetadata = metadata[entityType];
				if (!existingMetadata) continue;
				Object.assign(existingMetadata, params as Record<string, unknown>);
			}
		}
	}

	for (let j = 1; j < parsed.length; j++) {
		const stmt = parsed[j] as ParsedEntityStatement;
		const constraints = (stmt.payload as Record<string, unknown>).constraints as
			| Record<string, unknown>
			| undefined;

		if (constraints) {
			const constraintsResult = checkConstraints(
				constraints as Parameters<typeof checkConstraints>[0],
				j,
				parsed,
			);
			if (!constraintsResult.ok) {
				addError(
					errors,
					InternalErrorCode.ConstraintViolation,
					constraintsResult.error.description,
					{ statementIndex: j, checkNumber: 16 },
				);
			}

			const allowedTypes = (constraints as Record<string, unknown>).allowed_entity_types as
				| string[]
				| undefined;
			if (allowedTypes) {
				metadata = applyAllowedEntityTypes(allowedTypes, metadata);
			}
		}
	}

	let resolvedMetadata: Record<string, Record<string, unknown>> = metadata;

	if (subordinateStatements.length > 0) {
		const policyOptions = options?.customPolicyOperators
			? { customOperators: options.customPolicyOperators }
			: undefined;
		const policyResult = resolveMetadataPolicy(subordinateStatements, policyOptions);
		if (!policyResult.ok) {
			addError(errors, InternalErrorCode.MetadataPolicyError, policyResult.error.description, {
				checkNumber: 19,
			});
		} else if (Object.keys(policyResult.value).length > 0) {
			// Superior metadata already merged above; pass only leaf metadata + policy here.
			const applyResult = applyMetadataPolicy(
				metadata as FederationMetadata,
				policyResult.value,
				undefined,
				policyOptions,
			);
			if (!applyResult.ok) {
				addError(errors, InternalErrorCode.MetadataPolicyViolation, applyResult.error.description, {
					checkNumber: 24,
				});
			} else {
				resolvedMetadata = applyResult.value as Record<string, Record<string, unknown>>;
			}
		}
	}

	const trustMarks: ValidatedTrustMark[] = [];
	const leafTrustMarks = leafPayload.trust_marks as
		| Array<{ trust_mark_type: string; trust_mark: string }>
		| undefined;

	if (leafTrustMarks && leafTrustMarks.length > 0) {
		const trustMarkIssuers: Record<string, string[]> = {};
		let trustMarkOwners: Record<string, unknown> | undefined;
		const entityJwks: Record<string, JWKSet> = {};
		const taStatement = parsed[lastIdx] as ParsedEntityStatement;
		const taPayloadRec = taStatement.payload as Record<string, unknown>;
		if (taConfig) {
			entityJwks[lastIss] = taConfig.jwks;
		}
		if (taPayloadRec.iss === taPayloadRec.sub) {
			const issuers = taPayloadRec.trust_mark_issuers as Record<string, string[]> | undefined;
			if (issuers) {
				for (const [tmType, tmIssuers] of Object.entries(issuers)) {
					trustMarkIssuers[tmType] = tmIssuers;
				}
			}
			const owners = taPayloadRec.trust_mark_owners as Record<string, unknown> | undefined;
			if (owners) {
				trustMarkOwners = owners;
			}
		}
		for (const stmt of parsed) {
			if (stmt.payload.iss === stmt.payload.sub && stmt.payload.jwks) {
				entityJwks[stmt.payload.iss as string] = stmt.payload.jwks;
			}
		}

		for (const tmRef of leafTrustMarks) {
			const tmDecoded = decodeEntityStatement(tmRef.trust_mark);
			if (!tmDecoded.ok) {
				addError(
					errors,
					InternalErrorCode.TrustMarkInvalid,
					`Failed to decode published trust mark: ${tmDecoded.error.description}`,
					{ statementIndex: 0, field: "trust_marks", checkNumber: 16 },
				);
				continue;
			}

			const tmPayload = tmDecoded.value.payload as Record<string, unknown>;

			if (tmRef.trust_mark_type !== tmPayload.trust_mark_type) {
				addError(
					errors,
					InternalErrorCode.TrustMarkInvalid,
					`Published trust mark type does not match embedded trust mark type`,
					{ statementIndex: 0, field: "trust_marks", checkNumber: 16 },
				);
				continue;
			}

			const tmIss = tmPayload.iss as string | undefined;
			const jwksForIssuer = tmIss ? entityJwks[tmIss] : undefined;
			if (!jwksForIssuer) {
				addError(
					errors,
					InternalErrorCode.TrustMarkInvalid,
					`No trusted federation keys found for published trust mark issuer '${String(tmIss)}'`,
					{ statementIndex: 0, field: "trust_marks", checkNumber: 16 },
				);
				continue;
			}

			const tmResult = await validateTrustMark(tmRef.trust_mark, trustMarkIssuers, jwksForIssuer, {
				...options,
				expectedSubject: leafPayload.iss as string,
				...(trustMarkOwners
					? {
							trustMarkOwners: trustMarkOwners as Record<
								string,
								import("../schemas/trust-mark.js").TrustMarkOwner
							>,
						}
					: {}),
			});
			if (tmResult.ok) {
				trustMarks.push(tmResult.value);
			} else {
				addError(
					errors,
					InternalErrorCode.TrustMarkInvalid,
					`Invalid published trust mark: ${tmResult.error.description}`,
					{ statementIndex: 0, field: "trust_marks", checkNumber: 16 },
				);
			}
		}
	}

	const expiresAt = calculateChainExpiration(parsed);

	if (errors.length > 0) {
		if (options?.verboseErrors) {
			return { valid: false, errors };
		}
		return {
			valid: false,
			errors: [
				{
					code: InternalErrorCode.TrustChainInvalid,
					message: "Trust chain validation failed",
				},
			],
		};
	}

	const entityIdStr = leafPayload.iss as unknown as EntityId;
	const trustAnchorId = lastIss as unknown as EntityId;

	const validatedChain: ValidatedTrustChain = {
		statements: parsed,
		entityId: entityIdStr,
		trustAnchorId,
		expiresAt,
		resolvedMetadata,
		trustMarks,
	};

	return { valid: true, chain: validatedChain, errors };
}

/** Check if a validated trust chain has expired. */
export function isChainExpired(chain: ValidatedTrustChain, clock?: Clock): boolean {
	const now = (clock ?? defaultClock).now();
	return chain.expiresAt <= now;
}

/** Get remaining TTL in seconds, returning 0 if expired. */
export function chainRemainingTtl(chain: ValidatedTrustChain, clock?: Clock): number {
	const now = (clock ?? defaultClock).now();
	return Math.max(0, chain.expiresAt - now);
}

/** Human-readable chain description: hostnames joined with arrows. */
export function describeTrustChain(chain: ValidatedTrustChain): string {
	return chain.statements
		.map((s) => {
			try {
				return new URL(s.payload.sub as string).hostname;
			} catch {
				return String(s.payload.sub);
			}
		})
		.join(" ← ");
}

/** Select the chain with the fewest statements. */
export const shortestChain: ChainSelectionStrategy = (
	chains: ValidatedTrustChain[],
): ValidatedTrustChain => {
	return chains
		.slice()
		.sort((a, b) => a.statements.length - b.statements.length)[0] as ValidatedTrustChain;
};

/** Select the chain that expires last. */
export const longestExpiry: ChainSelectionStrategy = (
	chains: ValidatedTrustChain[],
): ValidatedTrustChain => {
	return chains.slice().sort((a, b) => b.expiresAt - a.expiresAt)[0] as ValidatedTrustChain;
};

/** Create a strategy that prefers chains terminating at the given trust anchor. */
export function preferTrustAnchor(taId: string): ChainSelectionStrategy {
	return (chains: ValidatedTrustChain[]): ValidatedTrustChain => {
		const matching = chains.filter((c) => c.trustAnchorId === taId);
		if (matching.length > 0) {
			return shortestChain(matching);
		}
		return shortestChain(chains);
	};
}
