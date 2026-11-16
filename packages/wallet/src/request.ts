/** Signed wallet presentation-request creation and prepared verifier-trust validation. */

import {
	completeTrustChainValidation,
	DEFAULT_CLOCK_SKEW_SECONDS,
	type JWKSet,
	type JwtSigner,
	nowSeconds,
	ok,
	type PreparedTrustChain,
	type Result,
	safeLogger,
	selectTrustChain,
	shortestChain,
	type TrustAnchorSet,
	type ValidatedTrustChain,
} from "@oidfed/core";
import { base64url } from "jose";
import { z } from "zod";
import { invokePolicy } from "./attestation.js";
import { decodeToken, matchesJwtType, signToken, verifyToken } from "./jwt.js";
import {
	CredentialVerifierMetadataSchema,
	type DcqlQuery,
	DcqlQuerySchema,
	normalizeReceivedDcqlQuery,
	ReceivedDcqlQuerySchema,
	requestScopeSchema,
} from "./metadata.js";
import {
	failure,
	operationExhausted,
	prepareVerifier,
	prepareVerifierCandidates,
	protocolKeys,
	roleMetadata,
	type WalletTrustOptions,
} from "./trust.js";

export interface WalletAuthorizationRequest {
	readonly client_id: string;
	readonly request_uri?: string;
	readonly request_uri_method?: "get" | "post";
	readonly request?: string;
}
export interface AuthorizationRequestOptions extends WalletTrustOptions {
	/** Wallet metadata issuer when dynamic discovery is used; absent means static discovery. */
	readonly walletIssuer?: string;
	readonly walletNonce?: string;
	/** Optional local freshness policy; requires iat when configured. */
	readonly maxRequestAgeSeconds?: number;
	/**
	 * Apply framework matching or refinement rules to the active request and effective queries.
	 * Wallet §6.3.1 leaves this profile choice open; contextual policy input alone
	 * does not authorize a different active query.
	 */
	readonly queryPolicy?: (
		context: {
			queries: readonly DcqlQuery[];
			request: Readonly<Record<string, unknown>>;
			chain: ValidatedTrustChain;
		},
		signal?: AbortSignal,
	) => boolean | Promise<boolean>;
	/**
	 * Approve transaction types and contents after request-level checks pass.
	 * Receives decoded data and active queries after any superior metadata override.
	 * Invoked during completion; the protocol engine handles presentation verification.
	 */
	readonly verifyTransactionData?: (
		context: { data: readonly Record<string, unknown>[]; queries: readonly DcqlQuery[] },
		signal?: AbortSignal,
	) => boolean | Promise<boolean>;
}

/** Local validation inputs for signing an OpenID4VP Authorization Request. */
export interface AuthorizationRequestCreationOptions extends AuthorizationRequestOptions {
	/**
	 * Application mapping for the signed scope. Required for transaction validation
	 * when scope selects the query and a validated superior override supplies none.
	 * Used locally; the Request Object retains its original scope parameter.
	 */
	readonly scopeQuery?: DcqlQuery;
}

declare const requestPreparationBrand: unique symbol;
/**
 * Process-local handle returned by prepareAuthorizationRequest. Keep the original
 * object for completion before expiresAt; copying or serializing it loses the
 * retained evidence. Preparation alone does not authorize the request.
 */
export interface PreparedAuthorizationRequest {
	readonly [requestPreparationBrand]: true;
	readonly verifierId: string;
	readonly expiresAt: number;
	readonly requestUri?: string;
}
export interface ValidatedWalletRequest {
	/** Protocol fields with request-supplied metadata and overridden query fields removed. */
	readonly request: Readonly<Record<string, unknown>>;
	readonly effectiveQueries: readonly DcqlQuery[];
	readonly querySource: "superior_metadata" | "verifier_metadata" | "metadata_policy" | "request";
	readonly verifierMetadata: Readonly<Record<string, unknown>>;
	readonly trustChain: ValidatedTrustChain;
}
const preparations = new WeakMap<
	PreparedAuthorizationRequest,
	{
		chain: PreparedTrustChain;
		keys: JWKSet;
		outer: WalletAuthorizationRequest;
		options: AuthorizationRequestOptions;
	}
>();
const validatedRequests = new WeakMap<
	ValidatedWalletRequest,
	{ metadata: Record<string, unknown>; expiresAt: number; options: WalletTrustOptions }
>();

function requestEvidenceIsCurrent(result: ValidatedWalletRequest): boolean {
	const saved = validatedRequests.get(result);
	return (
		!!saved && saved.expiresAt > nowSeconds(saved.options.clock) && !saved.options.signal?.aborted
	);
}

/**
 * Match a redirect against effective verifier metadata from an original, current validation result.
 */
export function validateResponseRedirect(
	result: ValidatedWalletRequest,
	uri: string,
): Result<true> {
	const saved = validatedRequests.get(result);
	if (!saved || !requestEvidenceIsCurrent(result))
		return failure("Unknown, expired, or cancelled verifier evidence");
	const checked = checkEndpoint(saved.metadata, "redirect_uris", uri);
	if (!checked.ok)
		safeLogger(saved.options.logger)?.warn(
			"redirect_uri MUST match the effective Credential Verifier redirect_uris metadata",
		);
	return checked;
}
const outerSchema = z.object({
	client_id: z.string().min(1),
	request_uri: z
		.url()
		.refine((value) => {
			const url = new URL(value);
			const authority = value.replace(/[\t\r\n]/g, "").match(/^[^:]*:[/\\]*([^/\\?#]*)/)?.[1];
			return (
				url.protocol === "https:" && !url.username && !url.password && !authority?.includes("@")
			);
		}, "Request URI must use HTTPS without userinfo")
		.optional(),
	request_uri_method: z.enum(["get", "post"]).optional(),
	request: z.string().optional(),
});
const requestSchema = z.looseObject({
	client_id: z.string().min(1),
	response_type: z.string().refine((value) => value.split(" ").includes("vp_token")),
	response_mode: z
		.string()
		.refine((value) => value.trim().length > 0, "Response mode must not be blank"),
	nonce: z.string().regex(/^[A-Za-z0-9._~-]+$/),
	state: z
		.string()
		.regex(/^[A-Za-z0-9._~-]+$/)
		.optional(),
	wallet_nonce: z.string().optional(),
	redirect_uri: z.string().optional(),
	response_uri: z.string().optional(),
	dcql_query: z.unknown().optional(),
	scope: requestScopeSchema.optional(),
	client_metadata: z.record(z.string(), z.unknown()).optional(),
});

function validateResponseParameters(request: z.infer<typeof requestSchema>): Result<true> {
	// OpenID4VP §8.2 applies to direct_post.jwt through §8.3.1 as well.
	if (request.response_uri !== undefined && request.redirect_uri !== undefined)
		return failure("response_uri and redirect_uri cannot appear together");
	const mode = request.response_mode;
	if (mode === "direct_post" || mode === "direct_post.jwt") {
		if (request.redirect_uri !== undefined)
			return failure(`${mode} requests cannot include redirect_uri`);
		if (request.response_uri === undefined)
			return failure(`${mode} response mode requires response_uri`);
	} else if (mode === "fragment" && request.redirect_uri === undefined) {
		return failure("fragment response mode requires redirect_uri");
	}
	// Wallet §6.3.1 defines these endpoints as HTTPS URLs in federation metadata.
	for (const [field, schema] of [
		["response_uri", CredentialVerifierMetadataSchema.shape.response_uris.unwrap().element],
		["redirect_uri", CredentialVerifierMetadataSchema.shape.redirect_uris.unwrap().element],
	] as const) {
		// RFC 6749 §3.1.2 also applies to response_uri through OpenID4VP §8.2.
		// Check the delimiter itself: URL.hash is empty for a trailing '#'.
		if (request[field]?.includes("#")) return failure(`${field} must not contain a fragment`);
		if (request[field] !== undefined && !schema.safeParse(request[field]).success)
			return failure(`${field} must be an HTTPS URL`);
	}
	return ok(true);
}

/** Require exact membership in the supplied effective verifier endpoint list. */
export function checkEndpoint(
	metadata: Readonly<Record<string, unknown>>,
	field: "request_uris" | "response_uris" | "redirect_uris",
	uri: unknown,
): Result<true> {
	if (typeof uri !== "string" || !Array.isArray(metadata[field]) || !metadata[field].includes(uri))
		return failure(`Endpoint is not registered in ${field}`);
	return ok(true);
}

/**
 * Establish candidate verifier evidence and return a process-local preparation handle.
 * Preparation does not accept the request; completion must authenticate its signed Request Object.
 */
export async function prepareRequest(
	outer: WalletAuthorizationRequest,
	anchors: TrustAnchorSet,
	options: AuthorizationRequestOptions,
	ignoreEmbeddedHint = false,
): Promise<Result<PreparedAuthorizationRequest>> {
	safeLogger(options?.logger)?.debug(
		"Preparing federation validation of an OpenID4VP Authorization Request",
	);

	const parsed = outerSchema.safeParse(outer);
	if (!parsed.success)
		return failure(
			`Invalid authorization request parameter: ${String(parsed.error.issues[0]?.path[0] ?? "request")}`,
		);
	if (!validRequestAgePolicy(options)) return failure("Invalid maxRequestAgeSeconds or clock skew");
	if (!outer.client_id.startsWith("openid_federation:"))
		return failure("A supported federation client identifier is required");
	if (
		(outer.request && outer.request_uri) ||
		(outer.request_uri_method !== undefined && !outer.request_uri)
	)
		return failure("Invalid request delivery parameters");
	const id = outer.client_id.slice("openid_federation:".length);
	let headerChain: readonly string[] | undefined;
	if (outer.request) {
		const decoded = decodeToken(outer.request, options);
		if (!decoded.ok) return decoded;
		// OpenID4VP §5: reject the wrong object type before consuming discovery hints.
		if (!matchesJwtType(decoded.value.header.typ, "oauth-authz-req+jwt"))
			return failure("Invalid Request Object type");

		// VP §5.9.3 also permits a trust_chain payload hint (Federation §12.1.1.1).
		const supplied = decoded.value.header.trust_chain ?? decoded.value.payload.trust_chain;
		if (decoded.value.header.trust_chain === null)
			return failure("Invalid Request Object trust_chain");
		if (supplied !== undefined) {
			if (!Array.isArray(supplied) || !supplied.every((item) => typeof item === "string"))
				return failure("Invalid Request Object trust_chain");
			headerChain = supplied as string[];
		}
	}
	const chains = await prepareVerifierCandidates(
		id,
		anchors,
		options,
		ignoreEmbeddedHint ? undefined : headerChain,
	);
	if (!chains.ok) return chains;
	const eligible: PreparedAuthorizationRequest[] = [];
	let rejected: Result<PreparedAuthorizationRequest> = failure("No eligible verifier chain");
	for (const chain of chains.value.chains) {
		const prepared = await prepareRequestEvidence(outer, id, chain, options);
		if (prepared.ok) eligible.push(prepared.value);
		else rejected = prepared;
	}
	if (operationExhausted(options))
		return failure("Wallet operation cancelled or exhausted its fetch budget");
	const canDiscover = chains.value.source === "hint" && !options.offline;
	if (!eligible.length)
		return canDiscover ? prepareRequest(outer, anchors, options, true) : rejected;
	const first = eligible[0];
	if (!first) return rejected;
	const prepared =
		eligible.length === 1
			? first
			: (Object.freeze({
					...first,
					expiresAt: Math.max(...eligible.map((item) => item.expiresAt)),
				}) as PreparedAuthorizationRequest);
	const saved = preparations.get(first);
	if (!saved) return failure("Missing request preparation");
	preparations.set(prepared, saved);
	preparationAlternatives.set(prepared, eligible);
	if (canDiscover) {
		// Retry an unusable hint only after request-context validation, using the same budget.
		preparationFallbacks.set(prepared, {
			outer: structuredClone(outer),
			anchors: new Map([...anchors].map(([id, keys]) => [id, structuredClone(keys)])),
			options: { ...options },
		});
	}
	return ok(prepared);
}

const preparationAlternatives = new WeakMap<
	PreparedAuthorizationRequest,
	readonly PreparedAuthorizationRequest[]
>();
const preparationFallbacks = new WeakMap<
	PreparedAuthorizationRequest,
	{
		outer: WalletAuthorizationRequest;
		anchors: TrustAnchorSet;
		options: AuthorizationRequestOptions;
	}
>();
async function prepareRequestEvidence(
	outer: WalletAuthorizationRequest,
	id: string,
	chain: PreparedTrustChain,
	options: AuthorizationRequestOptions,
): Promise<Result<PreparedAuthorizationRequest>> {
	const metadata = roleMetadata("openid_credential_verifier", id, chain);
	if (!metadata.ok) return metadata;
	if (outer.request_uri) {
		const endpoint = checkEndpoint(metadata.value, "request_uris", outer.request_uri);
		if (!endpoint.ok) {
			safeLogger(options.logger)?.warn(
				"request_uri MUST match the effective Credential Verifier request_uris metadata",
			);
			return endpoint;
		}
	}
	const keys = await protocolKeys(
		{ metadata: metadata.value, trustChain: chain },
		"openid_credential_verifier",
		options,
	);
	if (!keys.ok) return keys;
	const prepared = Object.freeze({
		verifierId: id,
		expiresAt: chain.expiresAt,
		...(outer.request_uri ? { requestUri: outer.request_uri } : {}),
	}) as PreparedAuthorizationRequest;
	preparations.set(prepared, {
		chain: chain,
		keys: structuredClone(keys.value),
		outer: structuredClone(outer),
		options: { ...options },
	});
	safeLogger(options?.logger)?.info("Wallet request preparation completed");
	return ok(prepared);
}

export interface AuthorizationRequestContext {
	readonly walletNonce?: string;
	/** Query resolved by the application's configured mapping for the signed scope. */
	readonly scopeQuery?: DcqlQuery;
}

/** Wallet Draft 05 §7.1.1 gives superior metadata priority over request queries. */
function hasSuperiorQueryOverride(chain: PreparedTrustChain): boolean {
	const superior = chain.statements[1]?.payload;
	return (
		superior?.iss !== superior?.sub &&
		superior?.metadata?.openid_credential_verifier?.dcql_queries !== undefined
	);
}

function requestedQueries(
	request: Record<string, unknown>,
	scopeQuery: DcqlQuery | undefined,
	received = false,
): Result<DcqlQuery[]> {
	const query = (received ? ReceivedDcqlQuerySchema : DcqlQuerySchema).safeParse(
		request.dcql_query !== undefined ? request.dcql_query : scopeQuery,
	);
	if (!query.success)
		return failure(
			request.dcql_query !== undefined
				? "Invalid DCQL query"
				: "Scope-to-DCQL mapping must be provided by the application",
		);
	return ok([received ? normalizeReceivedDcqlQuery(query.data) : query.data]);
}

/**
 * Check transaction structure and references (OpenID4VP §5.1), then enforce
 * the SD-JWT holder-binding requirement (Appendix B.3.3) for referenced queries.
 * The application still validates transaction types and actual presentations.
 * Decode only for inspection: Appendix B.3.3.1 hashes the original encoded
 * strings, so callers retain those strings in signed and validated requests.
 */
function validateTransactionData(
	value: unknown,
	queries: readonly DcqlQuery[],
): Result<Record<string, unknown>[]> {
	if (!Array.isArray(value) || !value.length) return failure("Unsupported transaction_data");
	const credentials = queries.flatMap((query) => query.credentials);
	const ids = new Set(credentials.map((credential) => credential.id));
	// IDs are unique within a query, but separate superior scenarios can reuse them.
	// Inspect every occurrence so metadata order cannot hide a binding-disabled query.
	const bindingDisabledIds = new Set(
		credentials
			.filter(
				(credential) =>
					credential.format === "dc+sd-jwt" &&
					credential.require_cryptographic_holder_binding === false,
			)
			.map((credential) => credential.id),
	);
	try {
		// Validate every slot, including sparse holes, before decoding or signing (§5.1).
		const encodedData = z.array(z.string()).parse(value);
		const data = encodedData.map((encoded) => {
			return z
				.looseObject({
					type: z.string(),
					credential_ids: z
						.array(z.string())
						.min(1)
						.refine((values) => values.every((id) => ids.has(id))),
				})
				.parse(JSON.parse(new TextDecoder().decode(base64url.decode(encoded))));
		});
		if (data.some((entry) => entry.credential_ids.some((id) => bindingDisabledIds.has(id))))
			return failure(
				"Transaction data requires cryptographic holder binding for SD-JWT credentials",
			);
		return ok(data);
	} catch {
		return failure("Malformed or unbound transaction data");
	}
}

/** Check only the queries used in this exchange, after superior overrides (VP Appendix B). */
function checkQueryFormats(
	queries: readonly DcqlQuery[],
	metadata: Record<string, unknown>,
): Result<true> {
	const formats = metadata.vp_formats_supported as Record<string, unknown>;
	if (
		queries.some((query) =>
			query.credentials.some((credential) => !Object.hasOwn(formats, credential.format)),
		)
	)
		return failure("Active query requests a format absent from effective verifier metadata");
	return ok(true);
}

/**
 * Complete the original preparation with the signed request and contextual policies.
 * Copied, expired, or cancelled handles fail; presentation processing remains the host engine's
 * responsibility.
 */
export async function completeRequest(
	prepared: PreparedAuthorizationRequest,
	jwt: string,
	context: AuthorizationRequestContext = {},
): Promise<Result<ValidatedWalletRequest>> {
	try {
		return await completeRequestImpl(prepared, jwt, context);
	} catch {
		safeLogger(preparations.get(prepared)?.options.logger)?.warn(
			"Wallet request completion failed",
		);
		return failure("Wallet request completion failed");
	}
}

async function completeRequestImpl(
	prepared: PreparedAuthorizationRequest,
	jwt: string,
	context: AuthorizationRequestContext,
): Promise<Result<ValidatedWalletRequest>> {
	const options = preparations.get(prepared)?.options;
	if (!options || prepared.expiresAt <= nowSeconds(options.clock) || operationExhausted(options))
		return failure("Unknown, expired, or cancelled request preparation");
	const outer = preparations.get(prepared)?.outer;
	if (outer?.request && outer.request !== jwt)
		return failure("Request Object differs from the inline prepared request");
	const alternatives = preparationAlternatives.get(prepared) ?? [prepared];
	const eligible: ValidatedWalletRequest[] = [];
	let rejected: Result<ValidatedWalletRequest> = failure("No eligible verifier chain");
	for (const candidate of alternatives) {
		const completed = await completeRequestCandidate(candidate, jwt, context);
		if (completed.ok) eligible.push(completed.value);
		else rejected = completed;
	}
	if (operationExhausted(options))
		return failure("Wallet operation cancelled or exhausted its fetch budget");
	if (!eligible.length) {
		const fallback = preparationFallbacks.get(prepared);
		if (!fallback) return rejected;
		const discovered = await prepareRequest(
			fallback.outer,
			fallback.anchors,
			fallback.options,
			true,
		);
		return discovered.ok ? completeRequest(discovered.value, jwt, context) : discovered;
	}
	// Later candidates can outlast an earlier result's Request Object or policy deadline.
	const current = eligible.filter(requestEvidenceIsCurrent);
	if (!current.length) return failure("Request validation expired or was cancelled");
	const selected = selectTrustChain(
		current.map((result) => result.trustChain),
		options,
		shortestChain,
	);
	if (!selected.ok) return selected;
	const result = current.find((result) => result.trustChain === selected.value);
	if (!result) return failure("Selected request chain is unavailable");
	// The selector checks chain expiry; request-specific freshness must also still hold.
	return requestEvidenceIsCurrent(result)
		? ok(result)
		: failure("Request validation expired or was cancelled");
}

async function completeRequestCandidate(
	prepared: PreparedAuthorizationRequest,
	jwt: string,
	context: AuthorizationRequestContext = {},
): Promise<Result<ValidatedWalletRequest>> {
	safeLogger(preparations.get(prepared)?.options.logger)?.debug(
		"Completing federation validation of an OpenID4VP Authorization Request",
	);

	const saved = preparations.get(prepared);
	if (
		!saved ||
		prepared.expiresAt <= nowSeconds(saved.options.clock) ||
		saved.options.signal?.aborted
	)
		return failure("Unknown, expired, or cancelled request preparation");
	if (saved.outer.request && saved.outer.request !== jwt)
		return failure("Request Object differs from the inline prepared request");
	const verified = await verifyToken(
		jwt,
		saved.keys,
		"oauth-authz-req+jwt",
		saved.options,
		saved.options.walletIssuer ?? "https://self-issued.me/v2",
	);
	if (!verified.ok) return verified;
	const deadline = requestDeadline(verified.value, saved.options);
	if (!deadline.ok) return deadline;
	const parsed = requestSchema.safeParse(verified.value);
	if (!parsed.success) return failure("Invalid OpenID4VP Request Object parameters");
	const request = parsed.data;
	const responseParameters = validateResponseParameters(request);
	if (!responseParameters.ok) return responseParameters;
	if (request.client_id !== saved.outer.client_id)
		return failure("Request Object client_id does not match the full outer identifier");
	if (
		saved.options.walletNonce !== undefined &&
		context.walletNonce !== undefined &&
		saved.options.walletNonce !== context.walletNonce
	)
		return failure("Expected wallet nonce changed during retrieval");
	const nonce = saved.options.walletNonce ?? context.walletNonce;
	if (nonce !== undefined && request.wallet_nonce !== nonce)
		return failure("Request Object wallet_nonce does not match");
	if ((request.scope === undefined) === (request.dcql_query === undefined))
		return failure("Exactly one DCQL query or scope is required");
	const contextual: Record<string, Record<string, unknown>> = {};
	if (saved.chain.pendingClaims.length && request.client_metadata?.dcql_query !== undefined) {
		const query = ReceivedDcqlQuerySchema.safeParse(request.client_metadata.dcql_query);
		if (!query.success) return failure("Invalid contextual DCQL query");
		// Wallet Draft 05 explicitly supplies this one field as policy input.
		contextual.openid_credential_verifier = { dcql_queries: [query.data] };
	}
	const completed = await completeTrustChainValidation(saved.chain, contextual);
	if (!completed.ok) return completed;
	const metadata = roleMetadata("openid_credential_verifier", prepared.verifierId, completed.value);
	if (!metadata.ok) return metadata;
	// Validate every supplied endpoint, even for an application-defined response mode.
	for (const [field, value] of [
		["request_uris", request.request_uri],
		["response_uris", request.response_uri],
		["redirect_uris", request.redirect_uri],
	] as const) {
		if (value !== undefined) {
			const allowed = checkEndpoint(metadata.value, field, value);
			if (!allowed.ok) {
				safeLogger(saved.options.logger)?.warn(
					`${field === "request_uris" ? "request_uri" : field === "response_uris" ? "response_uri" : "redirect_uri"} MUST match the effective Credential Verifier ${field} metadata`,
				);
				return allowed;
			}
		}
	}
	const superiorOverridesQuery = hasSuperiorQueryOverride(saved.chain);
	let requested: DcqlQuery[] | undefined;
	if (!superiorOverridesQuery) {
		const active = requestedQueries(request, context.scopeQuery, true);
		if (!active.ok) {
			if (
				request.scope !== undefined &&
				context.scopeQuery === undefined &&
				request.dcql_query === undefined
			)
				safeLogger(saved.options.logger)?.warn(
					"Provide a scopeQuery mapping for the OpenID4VP scope",
				);
			return active;
		}
		requested = active.value;
	}
	const queries =
		(metadata.value.dcql_queries as DcqlQuery[] | undefined)?.map(normalizeReceivedDcqlQuery) ??
		requested;
	if (!queries) return failure("Superior DCQL metadata did not produce an effective query");
	const supported = checkQueryFormats(requested ?? queries, metadata.value);
	if (!supported.ok) return supported;
	if (request.transaction_data !== undefined) {
		if (!saved.options.verifyTransactionData) {
			safeLogger(saved.options.logger)?.warn(
				"Provide verifyTransactionData to verify transaction_data",
			);
			return failure("Unsupported transaction_data");
		}
		const transactionQueries = requested ?? queries;
		const data = validateTransactionData(request.transaction_data, transactionQueries);
		if (!data.ok) return data;
		const accepted = await invokePolicy(
			saved.options.verifyTransactionData,
			{ data: data.value, queries: transactionQueries },
			saved.options,
			"Transaction Data verification",
		);
		if (!accepted.ok) return accepted;
	}
	const safeRequest: Record<string, unknown> = { ...request };
	// Applications receive the same normalized active query used by transaction checks.
	if (request.dcql_query !== undefined && requested) safeRequest.dcql_query = requested[0];
	delete safeRequest.client_metadata;
	delete safeRequest.iss;
	delete safeRequest.trust_chain;
	// Only the superior-metadata case mandates ignoring the requested query (Wallet §7.1.1).
	if (superiorOverridesQuery) {
		delete safeRequest.dcql_query;
		// Remove the plural request field too, so consumers cannot reuse it after the override.
		delete safeRequest.dcql_queries;
		delete safeRequest.scope;
	}
	const publishedQueries =
		saved.chain.statements[0]?.payload.metadata?.openid_credential_verifier?.dcql_queries;
	const querySource = superiorOverridesQuery
		? "superior_metadata"
		: metadata.value.dcql_queries !== undefined
			? publishedQueries !== undefined
				? "verifier_metadata"
				: "metadata_policy"
			: "request";
	if (saved.options.queryPolicy) {
		const accepted = await invokePolicy(
			saved.options.queryPolicy,
			{ queries, request: safeRequest, chain: completed.value },
			saved.options,
			"OpenID4VP presentation query policy",
		);
		if (!accepted.ok) return accepted;
	}
	if (
		saved.options.signal?.aborted ||
		Math.min(completed.value.expiresAt, deadline.value) <= nowSeconds(saved.options.clock)
	)
		return failure("Request validation expired or was cancelled");
	const result: ValidatedWalletRequest = {
		request: safeRequest,
		effectiveQueries: queries,
		querySource,
		verifierMetadata: {
			...metadata.value,
			...(metadata.value.dcql_queries !== undefined ? { dcql_queries: queries } : {}),
		},
		trustChain: completed.value,
	};
	validatedRequests.set(result, {
		metadata: structuredClone(metadata.value),
		expiresAt: Math.min(completed.value.expiresAt, deadline.value),
		options: saved.options,
	});
	safeLogger(preparations.get(prepared)?.options.logger)?.info(
		"Wallet request validation completed",
	);
	return ok(result);
}

function validRequestAgePolicy(options: AuthorizationRequestOptions): boolean {
	const age = options.maxRequestAgeSeconds;
	const skew = options.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;
	return (
		(age === undefined || (Number.isFinite(age) && age > 0)) && Number.isFinite(skew) && skew >= 0
	);
}

/** JWT dates retain RFC 7519 semantics; a maximum age is an explicit wallet policy. */
function requestDeadline(
	payload: Record<string, unknown>,
	options: AuthorizationRequestOptions,
	creating = false,
): Result<number> {
	if (!validRequestAgePolicy(options)) return failure("Invalid maxRequestAgeSeconds or clock skew");
	for (const name of ["iat", "exp", "nbf"]) {
		if (
			payload[name] !== undefined &&
			(typeof payload[name] !== "number" || !Number.isFinite(payload[name]))
		)
			return failure("Request Object dates must be finite NumericDates");
	}
	const now = nowSeconds(options.clock);
	const skew = creating ? 0 : (options.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS);
	const exp = payload.exp as number | undefined;
	const nbf = payload.nbf as number | undefined;
	if (creating && nbf !== undefined && exp !== undefined && nbf >= exp)
		return failure("Request Object has an empty validity interval");
	let deadline = exp === undefined ? Infinity : exp + skew;
	if (options.maxRequestAgeSeconds !== undefined) {
		const iat = payload.iat as number | undefined;
		if (iat === undefined || iat > now + skew)
			return failure("Request age policy requires an applicable iat");
		deadline = Math.min(deadline, iat + options.maxRequestAgeSeconds + skew);
	}
	return deadline > now
		? ok(deadline)
		: failure("Request Object is outside the allowed freshness window");
}

/**
 * Validate and sign federation-bound presentation request parameters.
 * The host owns request transport, credential selection, and presentation processing.
 */
export async function createRequest(
	id: string,
	request: Readonly<Record<string, unknown>>,
	signer: JwtSigner,
	options: AuthorizationRequestCreationOptions,
): Promise<Result<string>> {
	safeLogger(options?.logger)?.debug("Creating a signed OpenID4VP Authorization Request");

	const payload = {
		...request,
		client_id: `openid_federation:${id}`,
		aud: options.walletIssuer ?? "https://self-issued.me/v2",
		...(options.walletNonce !== undefined ? { wallet_nonce: options.walletNonce } : {}),
	};
	const deadline = requestDeadline(payload, options, true);
	if (!deadline.ok) return deadline;
	const parsed = requestSchema.safeParse(payload);
	if (!parsed.success) return failure("Invalid OpenID4VP Request Object parameters");
	const responseParameters = validateResponseParameters(parsed.data);
	if (!responseParameters.ok) return responseParameters;
	if ((parsed.data.scope === undefined) === (parsed.data.dcql_query === undefined))
		return failure("Exactly one DCQL query or scope is required");
	if (
		parsed.data.transaction_data === undefined &&
		parsed.data.dcql_query !== undefined &&
		!DcqlQuerySchema.safeParse(parsed.data.dcql_query).success
	)
		return failure("Invalid DCQL query");
	let transactionQueries: DcqlQuery[] | undefined;
	let effectiveMetadata: Record<string, unknown> | undefined;
	if (options.trustChain) {
		if (!options.trustAnchors?.size)
			return failure("Attaching a trust chain requires pinned anchors");
		const prepared = await prepareVerifier(id, options.trustAnchors, options);
		if (!prepared.ok) return prepared;
		const context: Record<string, Record<string, unknown>> = {};
		if (
			prepared.value.pendingClaims.length &&
			parsed.data.client_metadata?.dcql_query !== undefined
		) {
			const query = DcqlQuerySchema.safeParse(parsed.data.client_metadata.dcql_query);
			if (!query.success) return failure("Invalid contextual DCQL query");
			context.openid_credential_verifier = { dcql_queries: [query.data] };
		}
		const completed = await completeTrustChainValidation(prepared.value, context);
		if (!completed.ok) return completed;
		const metadata = roleMetadata("openid_credential_verifier", id, completed.value);
		if (!metadata.ok) return metadata;
		effectiveMetadata = metadata.value;
		if (hasSuperiorQueryOverride(prepared.value)) {
			// The validated statement establishes the override; completed metadata supplies
			// its policy-processed value. Ignored request queries cannot override it.
			transactionQueries = metadata.value.dcql_queries as DcqlQuery[] | undefined;
			if (!transactionQueries)
				return failure("Superior DCQL metadata did not produce an effective query");
		}
	}
	// OpenID4VP §5.3 requires state for non-holder-bound presentations outside the DC API.
	// Opaque scopes without a local mapping remain the protocol engine's responsibility.
	if (
		!transactionQueries &&
		(parsed.data.dcql_query !== undefined || options.scopeQuery !== undefined)
	) {
		const active = requestedQueries(parsed.data, options.scopeQuery);
		if (!active.ok) return active;
		transactionQueries = active.value;
	}
	if (parsed.data.transaction_data !== undefined) {
		if (!transactionQueries) {
			const active = requestedQueries(parsed.data, options.scopeQuery);
			if (!active.ok) return active;
			transactionQueries = active.value;
		}
		// Creation checks the request before signing; transaction-type approval and
		// presentation verification remain with the receiving wallet's application.
		const data = validateTransactionData(parsed.data.transaction_data, transactionQueries);
		if (!data.ok) return data;
	}
	if (effectiveMetadata && transactionQueries) {
		const supported = checkQueryFormats(transactionQueries, effectiveMetadata);
		if (!supported.ok) return supported;
	}
	if (
		parsed.data.state === undefined &&
		!["dc_api", "dc_api.jwt"].includes(parsed.data.response_mode) &&
		transactionQueries?.some((query) =>
			query.credentials.some(
				(credential) => credential.require_cryptographic_holder_binding === false,
			),
		)
	)
		return failure("state is required when requesting presentations without holder binding");

	const signed = await signToken(
		payload,
		"oauth-authz-req+jwt",
		signer,
		options,
		options.trustChain,
	);
	if (!signed.ok) return signed;
	// Trust resolution and an external signer can outlast the requested validity window.
	const currentDeadline = requestDeadline(payload, options, true);
	return currentDeadline.ok ? signed : currentDeadline;
}
