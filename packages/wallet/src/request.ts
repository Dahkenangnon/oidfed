import {
	completeTrustChainValidation,
	type JWKSet,
	type JwtSigner,
	nowSeconds,
	ok,
	type PreparedTrustChain,
	type Result,
	type TrustAnchorSet,
	type ValidatedTrustChain,
} from "@oidfed/core";
import { base64url } from "jose";
import { z } from "zod";
import { invokePolicy } from "./attestation.js";
import { decodeToken, signToken, verifyToken } from "./jwt.js";
import { type DcqlQuery, DcqlQuerySchema } from "./metadata.js";
import {
	failure,
	prepareVerifier,
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
	readonly queryPolicy?: (
		context: {
			queries: readonly DcqlQuery[];
			request: Readonly<Record<string, unknown>>;
			chain: ValidatedTrustChain;
		},
		signal?: AbortSignal,
	) => boolean | Promise<boolean>;
	/** Receives active presentation queries after any superior metadata override. */
	readonly verifyTransactionData?: (
		context: { data: readonly Record<string, unknown>[]; queries: readonly DcqlQuery[] },
		signal?: AbortSignal,
	) => boolean | Promise<boolean>;
}
declare const requestPreparationBrand: unique symbol;
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

export function validateResponseRedirect(
	result: ValidatedWalletRequest,
	uri: string,
): Result<true> {
	const saved = validatedRequests.get(result);
	if (!saved || saved.expiresAt <= nowSeconds(saved.options.clock) || saved.options.signal?.aborted)
		return failure("Unknown, expired, or cancelled verifier evidence");
	return checkEndpoint(saved.metadata, "redirect_uris", uri);
}
const outerSchema = z.object({
	client_id: z.string().min(1),
	request_uri: z.url().optional(),
	request_uri_method: z.enum(["get", "post"]).optional(),
	request: z.string().optional(),
});
const requestSchema = z.looseObject({
	client_id: z.string().min(1),
	response_type: z.string().refine((value) => value.split(" ").includes("vp_token")),
	response_mode: z.string(),
	nonce: z.string().regex(/^[A-Za-z0-9._~-]+$/),
	state: z
		.string()
		.regex(/^[A-Za-z0-9._~-]+$/)
		.optional(),
	wallet_nonce: z.string().optional(),
	redirect_uri: z.string().optional(),
	response_uri: z.string().optional(),
	dcql_query: z.unknown().optional(),
	scope: z.string().optional(),
	client_metadata: z.record(z.string(), z.unknown()).optional(),
});

export function checkEndpoint(
	metadata: Readonly<Record<string, unknown>>,
	field: "request_uris" | "response_uris" | "redirect_uris",
	uri: unknown,
): Result<true> {
	if (typeof uri !== "string" || !Array.isArray(metadata[field]) || !metadata[field].includes(uri))
		return failure(`Endpoint is not registered in ${field}`);
	return ok(true);
}

export async function prepareRequest(
	outer: WalletAuthorizationRequest,
	anchors: TrustAnchorSet,
	options: AuthorizationRequestOptions,
): Promise<Result<PreparedAuthorizationRequest>> {
	const parsed = outerSchema.safeParse(outer);
	if (!parsed.success || !outer.client_id.startsWith("openid_federation:"))
		return failure("A supported federation client identifier is required");
	if (
		(outer.request && outer.request_uri) ||
		(outer.request_uri_method !== undefined && !outer.request_uri)
	)
		return failure("Invalid request delivery parameters");
	const id = outer.client_id.slice("openid_federation:".length);
	let effectiveOptions = options;
	if (outer.request) {
		const decoded = decodeToken(outer.request, options);
		if (!decoded.ok) return decoded;
		const supplied = decoded.value.header.trust_chain;
		if (supplied !== undefined) {
			if (!Array.isArray(supplied) || !supplied.every((item) => typeof item === "string"))
				return failure("Invalid Request Object trust_chain");
			effectiveOptions = { ...options, trustChain: supplied as string[] };
		}
	}
	const chain = await prepareVerifier(id, anchors, effectiveOptions);
	if (!chain.ok) return chain;
	const metadata = roleMetadata("openid_credential_verifier", id, chain.value);
	if (!metadata.ok) return metadata;
	if (outer.request_uri) {
		const endpoint = checkEndpoint(metadata.value, "request_uris", outer.request_uri);
		if (!endpoint.ok) return endpoint;
	}
	const keys = await protocolKeys(
		{ metadata: metadata.value, trustChain: chain.value },
		"openid_credential_verifier",
		effectiveOptions,
	);
	if (!keys.ok) return keys;
	const prepared = Object.freeze({
		verifierId: id,
		expiresAt: chain.value.expiresAt,
		...(outer.request_uri ? { requestUri: outer.request_uri } : {}),
	}) as PreparedAuthorizationRequest;
	preparations.set(prepared, {
		chain: chain.value,
		keys: structuredClone(keys.value),
		outer: structuredClone(outer),
		options: { ...effectiveOptions },
	});
	return ok(prepared);
}

export interface AuthorizationRequestContext {
	readonly walletNonce?: string;
	/** Query resolved by the application's configured mapping for the signed scope. */
	readonly scopeQuery?: DcqlQuery;
}

export async function completeRequest(
	prepared: PreparedAuthorizationRequest,
	jwt: string,
	context: AuthorizationRequestContext = {},
): Promise<Result<ValidatedWalletRequest>> {
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
	const parsed = requestSchema.safeParse(verified.value);
	if (!parsed.success) return failure("Invalid OpenID4VP Request Object parameters");
	const request = parsed.data;
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
		const query = DcqlQuerySchema.safeParse(request.client_metadata.dcql_query);
		if (!query.success) return failure("Invalid contextual DCQL query");
		// Wallet Draft 05 explicitly supplies this one field as policy input.
		contextual.openid_credential_verifier = { dcql_queries: [query.data] };
	}
	const completed = await completeTrustChainValidation(saved.chain, contextual);
	if (!completed.ok) return completed;
	const metadata = roleMetadata("openid_credential_verifier", prepared.verifierId, completed.value);
	if (!metadata.ok) return metadata;
	const mode = request.response_mode;
	if (mode === "direct_post" || mode === "direct_post.jwt") {
		if (request.redirect_uri !== undefined)
			return failure("direct_post requests cannot include redirect_uri");
		const endpoint = checkEndpoint(metadata.value, "response_uris", request.response_uri);
		if (!endpoint.ok) return endpoint;
	} else if (request.redirect_uri !== undefined) {
		const endpoint = checkEndpoint(metadata.value, "redirect_uris", request.redirect_uri);
		if (!endpoint.ok) return endpoint;
	} else if (mode === "fragment") {
		return failure("fragment response mode requires redirect_uri");
	}
	// Validate every supplied endpoint, even for an application-defined response mode.
	for (const [field, value] of [
		["request_uris", request.request_uri],
		["response_uris", request.response_uri],
		["redirect_uris", request.redirect_uri],
	] as const) {
		if (value !== undefined) {
			const allowed = checkEndpoint(metadata.value, field, value);
			if (!allowed.ok) return allowed;
		}
	}
	const superior = saved.chain.statements[1]?.payload;
	const superiorQueries =
		superior?.iss !== superior?.sub
			? superior?.metadata?.openid_credential_verifier?.dcql_queries
			: undefined;
	const requestedQueries = (): Result<DcqlQuery[]> => {
		const query = DcqlQuerySchema.safeParse(
			request.dcql_query !== undefined ? request.dcql_query : context.scopeQuery,
		);
		if (!query.success)
			return failure(
				request.dcql_query !== undefined
					? "Invalid DCQL query"
					: "Scope-to-DCQL mapping must be provided by the application",
			);
		return ok([query.data]);
	};
	let queries: DcqlQuery[];
	if (metadata.value.dcql_queries !== undefined) {
		queries = metadata.value.dcql_queries as DcqlQuery[];
	} else {
		const active = requestedQueries();
		if (!active.ok) return active;
		queries = active.value;
	}
	if (request.transaction_data !== undefined) {
		if (
			!Array.isArray(request.transaction_data) ||
			!request.transaction_data.length ||
			!saved.options.verifyTransactionData
		)
			return failure("Unsupported transaction_data");
		let transactionQueries = queries;
		if (superiorQueries === undefined && metadata.value.dcql_queries !== undefined) {
			const active = requestedQueries();
			if (!active.ok) return active;
			transactionQueries = active.value;
		}
		try {
			const ids = new Set(
				transactionQueries.flatMap((query) => query.credentials.map((credential) => credential.id)),
			);
			const data = request.transaction_data.map((encoded: unknown) => {
				if (typeof encoded !== "string") throw new Error("Invalid transaction data encoding");
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
			const accepted = await invokePolicy(
				saved.options.verifyTransactionData,
				{ data, queries: transactionQueries },
				saved.options,
			);
			if (!accepted.ok) return accepted;
		} catch {
			return failure("Malformed or unbound transaction data");
		}
	}
	const safeRequest: Record<string, unknown> = { ...request };
	delete safeRequest.client_metadata;
	delete safeRequest.iss;
	// Only the superior-metadata case mandates ignoring the requested query (Wallet §7.1.1).
	if (superiorQueries !== undefined) {
		delete safeRequest.dcql_query;
		delete safeRequest.scope;
	}
	const publishedQueries =
		saved.chain.statements[0]?.payload.metadata?.openid_credential_verifier?.dcql_queries;
	const querySource =
		superiorQueries !== undefined
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
		);
		if (!accepted.ok) return accepted;
	}
	if (saved.options.signal?.aborted || completed.value.expiresAt <= nowSeconds(saved.options.clock))
		return failure("Request validation expired or was cancelled");
	const result: ValidatedWalletRequest = {
		request: safeRequest,
		effectiveQueries: queries,
		querySource,
		verifierMetadata: metadata.value,
		trustChain: completed.value,
	};
	validatedRequests.set(result, {
		metadata: structuredClone(metadata.value),
		expiresAt: completed.value.expiresAt,
		options: saved.options,
	});
	return ok(result);
}

export async function createRequest(
	id: string,
	request: Readonly<Record<string, unknown>>,
	signer: JwtSigner,
	options: AuthorizationRequestOptions,
): Promise<Result<string>> {
	const payload = {
		...request,
		client_id: `openid_federation:${id}`,
		aud: options.walletIssuer ?? "https://self-issued.me/v2",
		...(options.walletNonce !== undefined ? { wallet_nonce: options.walletNonce } : {}),
	};
	const parsed = requestSchema.safeParse(payload);
	if (!parsed.success) return failure("Invalid OpenID4VP Request Object parameters");
	if ((parsed.data.scope === undefined) === (parsed.data.dcql_query === undefined))
		return failure("Exactly one DCQL query or scope is required");
	if (
		parsed.data.dcql_query !== undefined &&
		!DcqlQuerySchema.safeParse(parsed.data.dcql_query).success
	)
		return failure("Invalid DCQL query");
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
	}
	return signToken(payload, "oauth-authz-req+jwt", signer, options, options.trustChain);
}
