/** Trust chain validation: verifies signatures, expiry, issuer-subject chaining, and metadata policy along the chain. */
import {
	DEFAULT_CLOCK_SKEW_SECONDS,
	DEFAULT_MAX_CHAIN_LENGTH,
	InternalErrorCode,
	JwtTyp,
	PolicyOperator,
	SUPPORTED_ALGORITHMS,
} from "../constants.js";
import { applyAllowedEntityTypes, checkConstraints } from "../constraints/index.js";
import { err, ok, type Result } from "../errors.js";
import { decodeEntityStatement, verifyEntityStatement } from "../jose/verify.js";
import { validateJwkSetUseRequirement } from "../jwks/use-requirement.js";
import { safeLogger } from "./../logging.js";
import { applyMetadataPolicy } from "../metadata-policy/apply.js";
import { resolveMetadataPolicy } from "../metadata-policy/merge.js";
import { findInvalidMetadataNullPaths } from "../metadata-values.js";
import {
	EntityConfigurationSchema,
	SubordinateStatementSchema,
} from "../schemas/entity-statement.js";
import { type JWK, type JWKSet, MetadataJWKSetSchema } from "../schemas/jwk.js";
import { type FederationMetadata, FederationMetadataValuesSchema } from "../schemas/metadata.js";
import {
	validateCriticalClaims,
	validateEntityStatementTimeClaims,
} from "../statement-validation.js";
import { evaluatePublishedTrustMarks } from "../trust-marks/evaluate.js";
import {
	type ChainSelectionStrategy,
	type Clock,
	type EntityId,
	type FederationOptions,
	nowSeconds,
	type ParsedEntityStatement,
	type TrustAnchorSet,
	type ValidatedTrustChain,
	type ValidationError,
	type ValidationResult,
} from "../types.js";
import { authorityMetadataErrors } from "./authority-metadata.js";
import { fetchEntityConfiguration } from "./fetch.js";

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

function decodeJwtPayloadJson(jwt: string): string | undefined {
	const payload = jwt.split(".")[1];
	if (!payload) return undefined;
	const base64 = payload.replace(/-/g, "+").replace(/_/g, "/");
	const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
	try {
		const binary = atob(padded);
		const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
		return new TextDecoder().decode(bytes);
	} catch {
		return undefined;
	}
}

function findDuplicateMetadataPolicyMembers(json: string): string[] {
	const duplicates: string[] = [];
	let index = 0;

	function skipWhitespace() {
		while (/\s/.test(json[index] ?? "")) index++;
	}

	function parseString(): string {
		const start = index;
		index++;
		while (index < json.length) {
			const char = json[index];
			if (char === "\\") {
				index += 2;
				continue;
			}
			if (char === '"') {
				index++;
				return JSON.parse(json.slice(start, index)) as string;
			}
			index++;
		}
		throw new Error("Unterminated JSON string");
	}

	function parsePrimitive() {
		while (index < json.length && !/[\s,\]}]/.test(json[index] ?? "")) index++;
	}

	function shouldCheckObject(path: readonly string[]): boolean {
		return path[0] === "metadata_policy" && path.length >= 1 && path.length <= 3;
	}

	function duplicatePath(path: readonly string[], key: string): string {
		return [...path, key].join(".");
	}

	function parseArray(path: string[]) {
		index++;
		skipWhitespace();
		if (json[index] === "]") {
			index++;
			return;
		}
		while (index < json.length) {
			parseValue(path);
			skipWhitespace();
			if (json[index] === "]") {
				index++;
				return;
			}
			if (json[index] !== ",") throw new Error("Expected comma in JSON array");
			index++;
			skipWhitespace();
		}
	}

	function parseObject(path: string[]) {
		const checkDuplicates = shouldCheckObject(path);
		const seen = new Set<string>();
		index++;
		skipWhitespace();
		if (json[index] === "}") {
			index++;
			return;
		}
		while (index < json.length) {
			if (json[index] !== '"') throw new Error("Expected JSON object member name");
			const key = parseString();
			if (checkDuplicates) {
				if (seen.has(key)) duplicates.push(duplicatePath(path, key));
				seen.add(key);
			}
			skipWhitespace();
			if (json[index] !== ":") throw new Error("Expected JSON object colon");
			index++;
			skipWhitespace();
			parseValue([...path, key]);
			skipWhitespace();
			if (json[index] === "}") {
				index++;
				return;
			}
			if (json[index] !== ",") throw new Error("Expected comma in JSON object");
			index++;
			skipWhitespace();
		}
	}

	function parseValue(path: string[]) {
		skipWhitespace();
		const char = json[index];
		if (char === "{") {
			parseObject(path);
		} else if (char === "[") {
			parseArray(path);
		} else if (char === '"') {
			parseString();
		} else {
			parsePrimitive();
		}
	}

	try {
		parseValue([]);
	} catch {
		return [];
	}
	return duplicates;
}

function addMetadataPolicyDuplicateMemberErrors(
	errors: ValidationError[],
	jwt: string,
	statementIndex: number,
) {
	const payloadJson = decodeJwtPayloadJson(jwt);
	if (!payloadJson) return;
	for (const duplicate of findDuplicateMetadataPolicyMembers(payloadJson)) {
		addError(
			errors,
			InternalErrorCode.TrustChainInvalid,
			`Duplicate metadata_policy member '${duplicate}' at statement ${statementIndex}`,
			{ statementIndex, field: "metadata_policy", checkNumber: 19 },
		);
	}
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

function addMetadataNullErrors(errors: ValidationError[], value: unknown, statementIndex: number) {
	for (const path of findInvalidMetadataNullPaths(value)) {
		addError(
			errors,
			InternalErrorCode.TrustChainInvalid,
			`Metadata value 'metadata.${path.join(".")}' MUST NOT be null at statement ${statementIndex}`,
			{ statementIndex, field: "metadata", checkNumber: 16 },
		);
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

/** Internal statement-shape check, shared with custom collection input validation. */
export function validateTrustMarkReferenceSyntax(
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

		// Sections 3.1.2 and 3.2 require signed-JWT syntax independently of Trust Mark evaluation.
		const segments = trustMarkJwt.split(".");
		const hasSignedCompactForm =
			segments.length === 3 &&
			segments.every(
				(segment) =>
					segment.length > 0 && segment.length % 4 !== 1 && !/[^A-Za-z0-9_-]/.test(segment),
			);
		const decoded = decodeEntityStatement(trustMarkJwt);
		if (
			!hasSignedCompactForm ||
			!decoded.ok ||
			typeof decoded.value.header.alg !== "string" ||
			decoded.value.header.alg.length === 0 ||
			decoded.value.header.alg === "none"
		) {
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
				}
			}
			addMetadataNullErrors(errors, payload.metadata, statementIndex);
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

interface TrustChainValidationOptions extends FederationOptions {
	verboseErrors?: boolean;
	explicitRegistrationAudience?: EntityId | string;
	/** Authenticate this registration EC against the candidate before resolving its metadata (Federation §12.2.2). */
	readonly explicitRegistrationRequest?: {
		readonly jwt: string;
		readonly audience: EntityId | string;
	};
	/** Independently trusted keys for issuers resolved outside this chain. */
	trustMarkIssuerKeys?: ReadonlyMap<string, JWKSet>;
}

/** Bound supplied work before copying statements or decoding JWTs (Federation §18.1). */
function chainLengthError(
	chain: readonly string[],
	options?: FederationOptions,
): string | undefined {
	const maximum = options?.maxChainLength ?? DEFAULT_MAX_CHAIN_LENGTH;
	if (!Number.isSafeInteger(maximum) || maximum <= 0)
		return "maxChainLength must be a positive safe integer";
	if (chain.length > maximum) return `Trust chain exceeds maxChainLength (${maximum})`;
	return undefined;
}

/** Validate a chain and report its published Trust Marks independently (Federation §§3.2, 7.3). */
export async function validateTrustChain(
	chain: ReadonlyArray<string>,
	trustAnchors: TrustAnchorSet,
	options?: TrustChainValidationOptions,
): Promise<ValidationResult> {
	safeLogger(options?.logger)?.debug("Starting validate trust chain");

	const limitError = chainLengthError(chain, options);
	if (limitError)
		return {
			valid: false,
			errors: [{ code: InternalErrorCode.TrustChainInvalid, message: limitError }],
		};
	const request = options?.explicitRegistrationRequest;
	if (!request) return validateTrustChainImpl(chain, trustAnchors, options, true);
	const fail = (message: string): ValidationResult => ({
		valid: false,
		errors: [{ code: InternalErrorCode.TrustChainInvalid, message }],
	});
	if (chain.length < 2) return fail("Explicit registration requires an Immediate Superior");
	const decoded = decodeEntityStatement(request.jwt);
	if (!decoded.ok) return fail(decoded.error.description);
	const superior = decodeEntityStatement(chain[1] as string);
	if (
		!superior.ok ||
		superior.value.payload.iss === superior.value.payload.sub ||
		superior.value.payload.sub !== decoded.value.payload.iss
	) {
		return fail(
			"Explicit registration requires a Subordinate Statement from the RP's Immediate Superior",
		);
	}
	if (decoded.value.payload.aud !== request.audience)
		return fail("Registration aud must match the OP");
	let entityConfigurations = options?.entityConfigurations;
	if (chain[0] !== request.jwt) {
		const { explicitRegistrationRequest: _request, ...evidenceOptions } = options ?? {};
		const evidence = await authenticateChainStatements(chain, trustAnchors, {
			...evidenceOptions,
			explicitRegistrationAudience: request.audience,
		});
		if (!evidence.valid) return evidence;
		entityConfigurations = evidence.entityConfigurations;
		if (String(evidence.statements[0]?.payload.iss) !== String(decoded.value.payload.iss)) {
			return fail("Registration request does not match the supplied chain subject");
		}
	}
	// Keep the signed request intact. Only its first-statement profile permits registration headers.
	return validateTrustChainImpl(
		[request.jwt, ...chain.slice(1)],
		trustAnchors,
		{
			...options,
			entityConfigurations,
			explicitRegistrationAudience: request.audience,
		},
		true,
	);
}

export interface ContextualMetadataClaim {
	readonly entityType: string;
	readonly parameter: string;
}

export interface PrepareTrustChainOptions
	extends Omit<TrustChainValidationOptions, "explicitRegistrationRequest"> {
	/** Only policies for absent values in these fields may remain pending. */
	readonly deferredClaims: readonly ContextualMetadataClaim[];
}

declare const preparedBrand: unique symbol;

/** Authenticated chain evidence with explicitly unfinished metadata policy checks. */
export interface PreparedTrustChain {
	readonly [preparedBrand]: true;
	readonly entityId: EntityId;
	readonly trustAnchorId: EntityId;
	readonly expiresAt: number;
	readonly resolvedMetadata: Readonly<Record<string, Record<string, unknown>>>;
	readonly statements: ReadonlyArray<ParsedEntityStatement>;
	readonly pendingClaims: readonly ContextualMetadataClaim[];
}

interface MetadataStage {
	deferred?: readonly ContextualMetadataClaim[];
	context?: Readonly<Record<string, Record<string, unknown>>>;
	pending: ContextualMetadataClaim[];
	entityConfigurations?: ReadonlyMap<string, string>;
}

/** Federation invariants apply after superior overrides and policies, including contextual completion. */
function validateResolvedMetadata(
	errors: ValidationError[],
	metadata: Record<string, Record<string, unknown>>,
	subject: string,
	pending: readonly ContextualMetadataClaim[] = [],
): void {
	const fail = (field: string, message: string) =>
		addError(
			errors,
			InternalErrorCode.MetadataPolicyViolation,
			`Invalid resolved metadata at ${field}: ${message}`,
			{
				field: `metadata.${field}`,
				checkNumber: 24,
			},
		);
	const shape = FederationMetadataValuesSchema.safeParse(metadata);
	if (!shape.success) {
		for (const issue of shape.error.issues) fail(issue.path.map(String).join("."), issue.message);
		return;
	}
	for (const type of ["openid_provider", "oauth_authorization_server"] as const) {
		const issuer = metadata[type]?.issuer;
		if (issuer !== undefined && issuer !== subject)
			fail(`${type}.issuer`, `issuer MUST match Entity Identifier '${subject}'`);
	}
	const op = metadata.openid_provider;
	const endpoint = op?.federation_registration_endpoint;
	let endpointUrl: URL | undefined;
	// The parameter is defined as a URL whenever supplied, even without explicit support.
	if (endpoint !== undefined) {
		if (typeof endpoint === "string" && endpoint.length > 0) {
			try {
				endpointUrl = new URL(endpoint);
			} catch {
				/* Report malformed URL values through the metadata validation result. */
			}
		}
		if (!endpointUrl)
			fail("openid_provider.federation_registration_endpoint", "endpoint MUST be a URL string");
	}
	if (
		Array.isArray(op?.client_registration_types_supported) &&
		op.client_registration_types_supported.includes("explicit")
	) {
		const deferred =
			endpoint === undefined &&
			pending.some(
				(claim) =>
					claim.entityType === "openid_provider" &&
					claim.parameter === "federation_registration_endpoint",
			);
		if (
			(endpoint === undefined && !deferred) ||
			(endpointUrl && (endpointUrl.protocol !== "https:" || endpointUrl.href.includes("#")))
		)
			fail(
				"openid_provider.federation_registration_endpoint",
				"explicit registration requires an HTTPS endpoint without a fragment",
			);
	}
	for (const [type, block] of Object.entries(metadata)) {
		if (block.jwks === undefined) continue;
		const jwks = MetadataJWKSetSchema.safeParse(block.jwks);
		if (!jwks.success) {
			for (const issue of jwks.error.issues) {
				const path = [type, "jwks", ...issue.path].map(String).join(".");
				fail(path, issue.message);
			}
			continue;
		}
		const use = validateJwkSetUseRequirement(jwks.data.keys);
		if (!use.ok) fail(`${type}.jwks`, use.error.description);
	}
}

const preparations = new WeakMap<
	PreparedTrustChain,
	{
		chain: readonly string[];
		anchors: TrustAnchorSet;
		options: TrustChainValidationOptions;
		pending: readonly ContextualMetadataClaim[];
	}
>();

function freezeEvidence<T>(value: T): T {
	if (value && typeof value === "object") {
		for (const nested of Object.values(value)) freezeEvidence(nested);
		Object.freeze(value);
	}
	return value;
}

function validationFailure(errors: readonly ValidationError[]) {
	return err({
		code: InternalErrorCode.TrustChainInvalid,
		description: errors.map((error) => error.message).join("; "),
	});
}

/** Authenticate a chain while reserving explicitly named, absent policy inputs. */
export async function prepareTrustChainValidation(
	chain: readonly string[],
	anchors: TrustAnchorSet,
	options: PrepareTrustChainOptions,
): Promise<Result<PreparedTrustChain>> {
	safeLogger(options?.logger)?.debug("Starting prepare trust chain validation");

	if (options.signal?.aborted)
		return validationFailure([
			{ code: InternalErrorCode.TrustChainInvalid, message: "Validation was cancelled" },
		]);
	const limitError = chainLengthError(chain, options);
	if (limitError)
		return validationFailure([{ code: InternalErrorCode.TrustChainInvalid, message: limitError }]);
	const savedChain = [...chain];
	const savedAnchors = new Map([...anchors].map(([id, anchor]) => [id, structuredClone(anchor)]));
	const { deferredClaims, ...validationOptions } = options;
	const savedOptions = {
		...validationOptions,
		...(options.entityConfigurations
			? { entityConfigurations: new Map(options.entityConfigurations) }
			: {}),
		...(options.trustMarkIssuerKeys
			? {
					trustMarkIssuerKeys: new Map(
						[...options.trustMarkIssuerKeys].map(([id, keys]) => [id, structuredClone(keys)]),
					),
				}
			: {}),
	};
	const stage: MetadataStage = { deferred: structuredClone(deferredClaims), pending: [] };
	const result = await validateTrustChainImpl(savedChain, savedAnchors, savedOptions, true, stage);
	if (!result.valid) return validationFailure(result.errors);
	// Completion rechecks the same signed ECs, including ones fetched during preparation.
	savedOptions.entityConfigurations = new Map(stage.entityConfigurations);
	if (options.signal?.aborted)
		return validationFailure([
			{ code: InternalErrorCode.TrustChainInvalid, message: "Validation was cancelled" },
		]);
	const prepared = freezeEvidence(
		structuredClone({
			entityId: result.chain.entityId,
			trustAnchorId: result.chain.trustAnchorId,
			expiresAt: result.chain.expiresAt,
			resolvedMetadata: result.chain.resolvedMetadata,
			statements: result.chain.statements,
			pendingClaims: stage.pending,
		}),
	) as unknown as PreparedTrustChain;
	preparations.set(prepared, {
		chain: savedChain,
		anchors: savedAnchors,
		options: savedOptions,
		pending: stage.pending,
	});
	return ok(prepared);
}

/** Finish the original chain's policies; contextual values cannot replace published metadata. */
export async function completeTrustChainValidation(
	prepared: PreparedTrustChain,
	context: Readonly<Record<string, Record<string, unknown>>> = {},
): Promise<Result<ValidatedTrustChain>> {
	safeLogger(preparations.get(prepared)?.options.logger)?.debug(
		"Starting complete trust chain validation",
	);

	const saved = preparations.get(prepared);
	if (!isJsonObject(context))
		return validationFailure([
			{
				code: InternalErrorCode.TrustChainInvalid,
				message: "Context must be a metadata object",
			},
		]);
	if (
		!saved ||
		saved.options.signal?.aborted ||
		prepared.expiresAt <= (saved.options.clock ?? defaultClock).now()
	) {
		return validationFailure([
			{
				code: InternalErrorCode.TrustChainInvalid,
				message: "Unknown, expired, or cancelled preparation",
			},
		]);
	}
	for (const [type, parameters] of Object.entries(context)) {
		if (
			!isJsonObject(parameters) ||
			Object.keys(parameters).some(
				(parameter) =>
					!saved.pending.some(
						(claim) => claim.entityType === type && claim.parameter === parameter,
					),
			)
		) {
			return validationFailure([
				{
					code: InternalErrorCode.TrustChainInvalid,
					message: "Context contains an unreserved metadata field",
				},
			]);
		}
	}
	const stage: MetadataStage = { context: structuredClone(context), pending: [] };
	const result = await validateTrustChainImpl(
		saved.chain,
		saved.anchors,
		saved.options,
		true,
		stage,
	);
	if (!result.valid) return validationFailure(result.errors);
	if (saved.options.signal?.aborted)
		return validationFailure([
			{ code: InternalErrorCode.TrustChainInvalid, message: "Validation was cancelled" },
		]);
	return ok(result.chain);
}

/** Internal collection primitive: mark syntax is mandatory; mark trust is evaluated separately. */
export function validateTrustChainStructure(
	chain: ReadonlyArray<string>,
	trustAnchors: TrustAnchorSet,
	options?: TrustChainValidationOptions,
): Promise<ValidationResult> {
	safeLogger(options?.logger)?.debug("Starting validate trust chain structure");

	return validateTrustChainImpl(chain, trustAnchors, options, false);
}

type PublicationValidationResult =
	| { valid: true; statement: ParsedEntityStatement; errors: readonly ValidationError[] }
	| { valid: false; errors: readonly ValidationError[] };

/** Internal publication check: authenticates the EC itself without establishing a trusted path. */
export async function validateEntityConfigurationPublication(
	jwt: string,
	options?: FederationOptions,
	registration?: { readonly audience: EntityId },
): Promise<PublicationValidationResult> {
	// Publication checks must not inherit registration exceptions from chain validation.
	const {
		explicitRegistrationAudience: _audience,
		explicitRegistrationRequest: _request,
		...publicationOptions
	} = (options ?? {}) as TrustChainValidationOptions;
	const result = await authenticateChainStatements(
		[jwt],
		new Map(),
		{
			...publicationOptions,
			...(registration
				? {
						explicitRegistrationAudience: registration.audience,
						explicitRegistrationRequest: { jwt, audience: registration.audience },
					}
				: {}),
		},
		true,
	);
	if (!result.valid) return result;
	const statement = result.statements[0] as ParsedEntityStatement;
	if (registration && statement.payload.aud !== registration.audience)
		return {
			valid: false,
			errors: [
				{
					code: InternalErrorCode.TrustChainInvalid,
					message: "Registration aud must match the OP",
				},
			],
		};
	return { valid: true, statement, errors: [] };
}

// Authentication is private: a path becomes a ValidatedTrustChain only after
// its subject's metadata and constraints have been processed.
type AuthenticatedStatements =
	| {
			valid: true;
			statements: ParsedEntityStatement[];
			expiresAt: number;
			entityConfigurations: ReadonlyMap<string, string>;
	  }
	| { valid: false; errors: readonly ValidationError[] };

async function authenticateChainStatements(
	chain: readonly string[],
	trustAnchors: TrustAnchorSet,
	options?: TrustChainValidationOptions,
	publicationOnly = false,
): Promise<AuthenticatedStatements> {
	const limitError = chainLengthError(chain, options);
	if (limitError)
		return {
			valid: false,
			errors: [{ code: InternalErrorCode.TrustChainInvalid, message: limitError }],
		};
	const errors: ValidationError[] = [];
	const configurationJwts = new Map(options?.entityConfigurations);
	const reportedAuthorities = new Set<string>();
	function checkAuthorityMetadata(statement: ParsedEntityStatement, statementIndex: number): void {
		const authorityErrors = authorityMetadataErrors(statement);
		if (authorityErrors.length && !reportedAuthorities.has(statement.payload.sub)) {
			reportedAuthorities.add(statement.payload.sub);
			safeLogger(options?.logger)?.warn(
				"Trust Anchors and Intermediates MUST publish fetch and list endpoints",
			);
		}
		for (const error of authorityErrors) errors.push({ ...error, statementIndex });
	}
	const clockSkew = options?.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;
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
		addMetadataPolicyDuplicateMemberErrors(errors, chain[j] as string, j);
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
		if (p.iat === undefined)
			addError(errors, InternalErrorCode.TrustChainInvalid, `Missing 'iat' at statement ${j}`, {
				statementIndex: j,
				field: "iat",
				checkNumber: 1,
			});
		if (p.exp === undefined)
			addError(errors, InternalErrorCode.TrustChainInvalid, `Missing 'exp' at statement ${j}`, {
				statementIndex: j,
				field: "exp",
				checkNumber: 1,
			});

		const timeClaims = validateEntityStatementTimeClaims(p, options);
		if (!timeClaims.ok) {
			addError(errors, timeClaims.error.code, timeClaims.error.description, {
				statementIndex: j,
				field: timeClaims.error.field,
				checkNumber: timeClaims.error.field === "iat" ? 4 : 5,
			});
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

		const criticalClaims = validateCriticalClaims(p, options?.understoodCriticalClaims);
		if (!criticalClaims.ok) {
			addError(errors, InternalErrorCode.TrustChainInvalid, criticalClaims.error.description, {
				statementIndex: j,
				field: "crit",
				checkNumber: 13,
			});
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

		if (h.trust_chain !== undefined && !(j === 0 && options?.explicitRegistrationRequest)) {
			addError(
				errors,
				InternalErrorCode.TrustChainInvalid,
				`Entity Statements MUST NOT contain trust_chain header at statement ${j}`,
				{ statementIndex: j, field: "trust_chain", checkNumber: 24 },
			);
		}
		if (h.peer_trust_chain !== undefined && !(j === 0 && options?.explicitRegistrationRequest)) {
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

	if (publicationOnly)
		return errors.length
			? { valid: false, errors }
			: {
					valid: true,
					statements: parsed,
					expiresAt: calculateChainExpiration(parsed),
					entityConfigurations: configurationJwts,
				};

	// Federation §§10.1 and 17.1 require each path to be loop-free. The closing
	// anchor EC describes the anchor already introduced by its Subordinate Statement.
	const seenEntities = new Set([leafPayload.sub as string]);
	for (let j = 1; j < parsed.length; j++) {
		const payload = (parsed[j] as ParsedEntityStatement).payload;
		const previous = (parsed[j - 1] as ParsedEntityStatement).payload;
		if (
			j === parsed.length - 1 &&
			payload.iss === payload.sub &&
			previous.iss !== previous.sub &&
			previous.iss === payload.sub
		)
			continue;
		if (seenEntities.has(payload.iss)) {
			addError(
				errors,
				InternalErrorCode.LoopDetected,
				`Loop detected at statement ${j}: Entity '${payload.iss}' occurs more than once`,
				{ statementIndex: j, field: "iss" },
			);
			return {
				valid: false,
				errors: options?.verboseErrors
					? errors
					: [
							{
								code: InternalErrorCode.TrustChainInvalid,
								message: "Trust chain validation failed",
							},
						],
			};
		}
		seenEntities.add(payload.iss);
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

	// Federation §§3.2 and 4 also require the anchor EC's signature to verify
	// with its own published key. A single-statement chain was checked at index 0.
	if (hasTrailingTrustAnchorEc && lastIdx > 0) {
		const selfVerify = await verifyEntityStatement(
			chain[lastIdx] as string,
			last.payload.jwks as JWKSet,
			verifyOptions,
		);
		if (!selfVerify.ok) {
			addError(
				errors,
				InternalErrorCode.SignatureInvalid,
				`TA EC self-signature invalid: ${selfVerify.error.description}`,
				{ statementIndex: lastIdx, field: "jwks", checkNumber: 15 },
			);
		}
	}

	// Federation §4.1 permits a configured anchor to have superiors. Its signed
	// authority_hints declare those relationships; configured trust ends this chain.
	if (hasTrailingTrustAnchorEc && trustAnchors.has(lastIss as EntityId)) {
		if (errors.length === 0) {
			checkAuthorityMetadata(last, lastIdx);
		}
		const hasSuperiors =
			Array.isArray(lastPayload.authority_hints) && lastPayload.authority_hints.length > 0;
		// Section 3.1.2 forbids trust_anchor_hints on anchors with no superiors.
		if (!hasSuperiors && lastPayload.trust_anchor_hints !== undefined) {
			addError(
				errors,
				InternalErrorCode.TrustChainInvalid,
				`Trust Anchor EC with no superiors MUST NOT contain trust_anchor_hints`,
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

	// Intermediate ECs are auxiliary evidence, not entries in the serialized chain.
	// Authenticate the supplied path before following any of its identifiers online.
	let expiresAt = calculateChainExpiration(parsed);
	if (errors.length === 0) {
		let remainingFetches = options?.maxTotalFetches ?? 50;
		if (!Number.isSafeInteger(remainingFetches) || remainingFetches < 0) {
			addError(
				errors,
				InternalErrorCode.TrustChainInvalid,
				"maxTotalFetches must be a non-negative safe integer",
			);
		}
		const transport = options?.httpClient ?? fetch;
		const fetchOptions: FederationOptions = {
			...options,
			httpClient: async (input, init) => {
				if (options?.signal?.aborted || init?.signal?.aborted)
					throw new DOMException("Validation was cancelled", "AbortError");
				if (remainingFetches <= 0) throw new Error("Subject EC fetch budget exhausted");
				remainingFetches--;
				return transport(input, init);
			},
		};
		// Serial retrieval bounds concurrency to one and stops on the first invalid edge.
		for (let j = 1; j < parsed.length && errors.length === 0; j++) {
			if (options?.signal?.aborted) {
				addError(errors, InternalErrorCode.Timeout, "Validation was cancelled");
				break;
			}
			const ss = (parsed[j] as ParsedEntityStatement).payload;
			if (ss.iss === ss.sub) continue;
			let subject = leaf;
			if (ss.sub !== leaf.payload.sub) {
				let jwt = configurationJwts.get(ss.sub);
				if (jwt === undefined) {
					try {
						const fetched = await fetchEntityConfiguration(
							ss.sub as unknown as EntityId,
							fetchOptions,
						);
						if (!fetched.ok) {
							addError(
								errors,
								fetched.error.code,
								`Unable to obtain subject EC '${ss.sub}': ${fetched.error.description}`,
								{ statementIndex: j, field: "authority_hints", checkNumber: 6 },
							);
							break;
						}
						jwt = fetched.value;
						configurationJwts.set(ss.sub, jwt);
					} catch (cause) {
						addError(
							errors,
							InternalErrorCode.Network,
							`Unable to obtain subject EC '${ss.sub}': ${cause instanceof Error ? cause.message : "Retrieval failed"}`,
							{ statementIndex: j, field: "authority_hints", checkNumber: 6 },
						);
						break;
					}
				}
				const publication = await validateEntityConfigurationPublication(jwt, options);
				if (!publication.valid) {
					for (const error of publication.errors)
						addError(errors, error.code, `Invalid subject EC '${ss.sub}': ${error.message}`, {
							statementIndex: j,
							field: error.field ?? "authority_hints",
							checkNumber: error.checkNumber ?? 6,
						});
					break;
				}
				subject = publication.statement;
				if (subject.payload.iss !== ss.sub || subject.payload.sub !== ss.sub) {
					addError(
						errors,
						InternalErrorCode.TrustChainInvalid,
						`Subject EC identity does not match '${ss.sub}'`,
						{ statementIndex: j, field: "sub", checkNumber: 6 },
					);
					break;
				}
				// Bind the self-published EC to the keys attested by this authenticated SS.
				const bound = await verifyEntityStatement(jwt, ss.jwks as JWKSet, verifyOptions);
				if (!bound.ok) {
					addError(
						errors,
						InternalErrorCode.SignatureInvalid,
						`Subject EC '${ss.sub}' does not verify with the chain's subject keys: ${bound.error.description}`,
						{ statementIndex: j, field: "jwks", checkNumber: 6 },
					);
					break;
				}
				expiresAt = Math.min(expiresAt, subject.payload.exp);
				checkAuthorityMetadata(subject, j);
			}
			const subjectHints = subject.payload.authority_hints;
			if (!subjectHints?.includes(ss.iss)) {
				addError(
					errors,
					InternalErrorCode.TrustChainInvalid,
					`SS issuer '${ss.iss}' not found in subject's authority_hints at statement ${j}`,
					{ statementIndex: j, field: "authority_hints", checkNumber: 6 },
				);
			}
		}
	}
	if (options?.signal?.aborted && errors.length === 0)
		addError(errors, InternalErrorCode.Timeout, "Validation was cancelled");

	if (errors.length > 0) {
		safeLogger(options?.logger)?.warn("Trust chain validation failed");
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

	return { valid: true, statements: parsed, expiresAt, entityConfigurations: configurationJwts };
}

async function validateTrustChainImpl(
	chain: readonly string[],
	trustAnchors: TrustAnchorSet,
	options: TrustChainValidationOptions | undefined,
	verifyMarks: boolean,
	stage?: MetadataStage,
): Promise<ValidationResult> {
	const authenticated = await authenticateChainStatements(chain, trustAnchors, options);
	if (!authenticated.valid) return authenticated;
	if (stage) stage.entityConfigurations = authenticated.entityConfigurations;
	const parsed = authenticated.statements;
	const errors: ValidationError[] = [];
	let failureMessage: string | undefined;
	const leafPayload = (parsed[0] as ParsedEntityStatement).payload as Record<string, unknown>;
	const lastIdx = parsed.length - 1;
	const lastPayload = (parsed[lastIdx] as ParsedEntityStatement).payload;
	const lastIss = lastPayload.iss as string;
	const hasTrailingTrustAnchorEc = lastPayload.iss === lastPayload.sub;

	const subordinateStatements = hasTrailingTrustAnchorEc ? parsed.slice(1, -1) : parsed.slice(1);

	let metadata = structuredClone(leafPayload.metadata ?? {}) as Record<
		string,
		Record<string, unknown>
	>;

	// Merge Immediate Superior's SS metadata before applying allowed_entity_types constraints,
	// so the filter sees the fully merged metadata as required by the spec.
	const immediateSuperior = subordinateStatements[0];
	if (immediateSuperior) {
		const immSupMeta = (immediateSuperior.payload as Record<string, unknown>).metadata as
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
				failureMessage ??= "Trust Chain constraints validation failed";
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
			failureMessage ??= "Metadata Policy resolution failed";
			addError(errors, InternalErrorCode.MetadataPolicyError, policyResult.error.description, {
				checkNumber: 19,
			});
		} else if (Object.keys(policyResult.value).length > 0) {
			for (const [type, values] of Object.entries(stage?.context ?? {})) {
				for (const [parameter, value] of Object.entries(values)) {
					if (metadata[type]?.[parameter] === undefined && metadata[type]) {
						metadata[type][parameter] = value;
					}
				}
			}
			for (const claim of stage?.deferred ?? []) {
				const policies = policyResult.value[claim.entityType];
				if (
					metadata[claim.entityType] &&
					metadata[claim.entityType]?.[claim.parameter] === undefined &&
					policies?.[claim.parameter] !== undefined
				) {
					delete policies[claim.parameter];
					stage?.pending.push({ ...claim });
				}
			}
			// Registration retains the request's Entity Types (§12.2.5). A policy
			// for another role does not declare that role on the RP's behalf.
			const applicablePolicy = options?.explicitRegistrationRequest
				? Object.fromEntries(
						Object.entries(policyResult.value).filter(([type]) => Object.hasOwn(metadata, type)),
					)
				: policyResult.value;
			// Superior metadata already merged above; pass only leaf metadata + policy here.
			const applyResult = applyMetadataPolicy(
				metadata as FederationMetadata,
				applicablePolicy,
				undefined,
				policyOptions,
			);
			if (!applyResult.ok) {
				failureMessage ??= "Metadata Policy application failed";
				addError(errors, InternalErrorCode.MetadataPolicyViolation, applyResult.error.description, {
					checkNumber: 24,
				});
			} else {
				resolvedMetadata = applyResult.value as Record<string, Record<string, unknown>>;
			}
		}
	}

	// Federation §§5 and 6.1.4.2 apply to the final metadata, including
	// chains resolved through superior overrides without a metadata policy.
	if (errors.length === 0) {
		validateResolvedMetadata(errors, resolvedMetadata, leafPayload.iss as string, stage?.pending);
		if (errors.length > 0) failureMessage = "Resolved metadata validation failed";
	}

	// Federation §§3.2 and 7.3 distinguish reference syntax from trust in a mark.
	const trustMarkEvaluations =
		errors.length === 0
			? await evaluatePublishedTrustMarks(parsed, trustAnchors, options, verifyMarks)
			: [];
	const trustMarks = trustMarkEvaluations.flatMap((result) =>
		result.status === "verified" ? [result.mark] : [],
	);

	const expiresAt = authenticated.expiresAt;

	if (errors.length > 0) {
		safeLogger(options?.logger)?.warn(failureMessage ?? "Trust chain validation failed");
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
		trustMarkEvaluations,
	};

	if (!stage?.deferred) safeLogger(options?.logger)?.info("Trust chain validated");
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
