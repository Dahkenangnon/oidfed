/** Managed Trust Mark issuance, revocation, eligibility, and HTTP endpoints. */

import { freezeSnapshot, isJsonData, setOwn } from "../callbacks.js";
import {
	DEFAULT_DELEGATION_TTL_SECONDS,
	DEFAULT_MAX_REQUEST_BODY_BYTES,
	JwtTyp,
	MediaType,
} from "../constants.js";
import {
	authenticatedEndpointCaller,
	type EndpointAuthenticationConfig,
} from "../endpoint-authentication.js";
import type { Result } from "../errors.js";
import { selectHistoricalVerificationKey } from "../federation-api/index.js";
import type { FederationKeyLifecycleProvider, FederationKeyProvider } from "../federation-keys.js";
import {
	errorResponse,
	jsonResponse,
	jwtResponse,
	readBodyWithLimit,
	requireMethod,
} from "../http.js";
import { signEntityStatement } from "../jose/sign.js";
import type { JwtSigner } from "../jose/signer.js";
import { decodeEntityStatement } from "../jose/verify.js";
import { safeLogger } from "../logging.js";
import { EntityIdSchema } from "../schemas/entity-id.js";
import type { TrustMarkStatusResponsePayload } from "../schemas/entity-statement.js";
import type { TrustMarkOwner } from "../schemas/trust-mark.js";
import { assertPositiveTtlSeconds } from "../ttl.js";
import { type EntityId, entityId, type FederationOptions, nowSeconds } from "../types.js";
import { type TrustMarkIssuerContext, trustMarkIssuerContext } from "./evidence.js";
import { validateTrustMark } from "./index.js";
import { type SignTrustMarkOptions, signTrustMark, type TrustMarkLifetime } from "./sign.js";
import type { TrustMarkRecord, TrustMarkStorage, TrustMarkStore } from "./storage.js";

export interface TrustMarkIssuanceOptions extends TrustMarkLifetime {
	readonly renewal?: "reuse" | "renew";
	readonly logoUri?: string;
	readonly ref?: string;
	readonly additionalClaims?: Readonly<Record<string, unknown>>;
	readonly typ?: string;
}
export interface TrustMarkStatusAssessment {
	readonly payload: Readonly<TrustMarkStatusResponsePayload>;
	readonly verificationExpiresAt?: number;
}
export interface TrustMarkStatusPolicyContext {
	readonly baseStatus: string;
	readonly record: Readonly<TrustMarkRecord>;
}
export type TrustMarkStatusPolicy = (context: TrustMarkStatusPolicyContext) =>
	| { readonly status: string; readonly additionalClaims?: Readonly<Record<string, unknown>> }
	| Promise<{
			readonly status: string;
			readonly additionalClaims?: Readonly<Record<string, unknown>>;
	  }>;
export interface TrustMarkRequestContext {
	readonly endpoint: "status" | "list" | "retrieval";
	readonly issuer: string;
	readonly caller?: string;
	readonly parameters: Readonly<Record<string, readonly string[]>>;
}
export type TrustMarkRequestExtension = (
	values: readonly string[],
	context: Readonly<TrustMarkRequestContext>,
) => Result<void> | Promise<Result<void>>;
export interface TrustMarkIssuerConfig {
	readonly trustMarkRequestExtensions?: Readonly<Record<string, TrustMarkRequestExtension>>;
	readonly storage: TrustMarkStore;
	readonly authentication?: Omit<EndpointAuthenticationConfig, "receiverEntityId" | "methods">;
	readonly defaults?: TrustMarkIssuanceOptions;
	readonly trustMarkSigner?: (
		context: Readonly<{ issuer: string; subject: string; trustMarkType: string }>,
	) => JwtSigner | Promise<JwtSigner>;
	readonly trustMarkDefaults?: Readonly<Record<string, TrustMarkIssuanceOptions>>;
	readonly delegations?: Readonly<Record<string, string>>;
	/** Independent issuer trust supplies owner keys for delegated issuance. */
	readonly issuerEvidence?: readonly TrustMarkIssuerContext[];
	readonly trustMarkStatusPolicy?: TrustMarkStatusPolicy;
}
export interface TrustMarkIssuerServiceOptions extends TrustMarkIssuerConfig {
	readonly issuer: string;
	readonly statusEndpointPublished?: boolean;
	readonly keyProvider: FederationKeyProvider;
	readonly options?: FederationOptions;
	/** Local Trust Anchor policy; do not populate from unverified token claims. */
	readonly trustMarkOwners?: Readonly<Record<string, TrustMarkOwner>>;
	readonly trustMarkIssuers?: Readonly<Record<string, readonly string[]>>;
}

function validateIssuanceOptions(options: TrustMarkIssuanceOptions): void {
	if (!options || !isJsonData(options) || Array.isArray(options))
		throw new TypeError("Issuance options must be JSON object data");
	if (options.noExpiry !== undefined && typeof options.noExpiry !== "boolean")
		throw new TypeError("noExpiry must be a boolean");
	if (options.ttlSeconds !== undefined)
		assertPositiveTtlSeconds(options.ttlSeconds, "ttlSeconds", "finite");
	if (options.noExpiry && options.ttlSeconds !== undefined)
		throw new TypeError("noExpiry and ttlSeconds conflict");
	if (options.renewal !== undefined && options.renewal !== "reuse" && options.renewal !== "renew")
		throw new TypeError("Invalid renewal mode");
	if (options.additionalClaims !== undefined) {
		if (!options.additionalClaims || Array.isArray(options.additionalClaims))
			throw new TypeError("Additional claims must be JSON object data");
		for (const name of Object.keys(options.additionalClaims))
			if (
				["iss", "sub", "trust_mark_type", "iat", "exp", "logo_uri", "ref", "delegation"].includes(
					name,
				)
			)
				throw new TypeError("Reserved Trust Mark claim");
	}
}
const sameJson = (a: unknown, b: unknown): boolean => {
	if (Object.is(a, b)) return true;
	if (!a || !b || typeof a !== "object" || typeof b !== "object") return false;
	const ak = Object.keys(a),
		bk = Object.keys(b);
	return (
		ak.length === bk.length &&
		ak.every(
			(k) =>
				Object.hasOwn(b, k) &&
				sameJson((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]),
		)
	);
};

/** Shared managed issuance and eligibility for Leaf and Authority hosts. */
export class TrustMarkIssuerService {
	readonly issuer: EntityId;
	private readonly defaults: TrustMarkIssuanceOptions;
	private readonly typeDefaults: Readonly<Record<string, TrustMarkIssuanceOptions>>;
	private delegations: Readonly<Record<string, string>>;
	private version = 0;
	private statusNotice = false;
	private readonly extensions: ReadonlyMap<string, TrustMarkRequestExtension>;
	private ownerPolicy: Readonly<Record<string, TrustMarkOwner>>;
	private issuerPolicy: Readonly<Record<string, readonly string[]>> | undefined;
	/** Validate issuer configuration and detach owner, issuer, delegation, and lifetime policies. */
	constructor(private readonly config: TrustMarkIssuerServiceOptions) {
		this.issuer = entityId(config.issuer);
		this.extensions = new Map(Object.entries(config.trustMarkRequestExtensions ?? {}));
		for (const [name, handler] of this.extensions)
			if (
				[
					"trust_mark_type",
					"trust_mark",
					"sub",
					"client_assertion",
					"client_assertion_type",
					"client_id",
					"client_secret",
				].includes(name) ||
				typeof handler !== "function"
			)
				throw new TypeError("Invalid Trust Mark request extension");
		this.ownerPolicy = freezeSnapshot(structuredClone(config.trustMarkOwners ?? {}));
		this.issuerPolicy = config.trustMarkIssuers
			? freezeSnapshot(structuredClone(config.trustMarkIssuers))
			: undefined;
		this.config = {
			...config,
			...(config.issuerEvidence
				? {
						issuerEvidence: config.issuerEvidence.map((evidence) =>
							evidence.kind === "federation" ? evidence : freezeSnapshot(structuredClone(evidence)),
						),
					}
				: {}),
			...(config.options
				? {
						options: {
							...config.options,
							...(config.options.trustMarkProfiles
								? {
										trustMarkProfiles: config.options.trustMarkProfiles.map((profile) =>
											Object.freeze({
												...profile,
												trustMarkTypes: Object.freeze([...profile.trustMarkTypes]),
											}),
										),
									}
								: {}),
						},
					}
				: {}),
		};
		validateIssuanceOptions(config.defaults ?? {});
		for (const options of Object.values(config.trustMarkDefaults ?? {}))
			validateIssuanceOptions(options);
		this.defaults = freezeSnapshot(structuredClone(config.defaults ?? {}));
		this.typeDefaults = freezeSnapshot(structuredClone(config.trustMarkDefaults ?? {}));
		if (Object.values(config.delegations ?? {}).some((value) => typeof value !== "string"))
			throw new TypeError("Invalid Trust Mark delegation configuration");
		this.delegations = freezeSnapshot(structuredClone(config.delegations ?? {}));
	}
	private owners(type: string): Record<string, TrustMarkOwner> {
		const evidence = this.config.issuerEvidence?.find(
			(e) =>
				e.issuer === this.issuer &&
				(e.kind === "federation"
					? e.trustMarkType === type
					: e.allowedTrustMarkTypes.includes(type)),
		);
		if (evidence) {
			const trusted = trustMarkIssuerContext(evidence, type, this.config.options);
			if (!trusted.ok) throw new Error(trusted.error.description);
			return trusted.value.owners;
		}
		return structuredClone(this.ownerPolicy);
	}
	private authorize(type: string) {
		if (!type) throw new TypeError("A Trust Mark type is required");
		const issuers = this.issuerPolicy;
		if (issuers && Object.hasOwn(issuers, type)) {
			const allowed = issuers[type];
			if (!Array.isArray(allowed) || !allowed.every((value) => typeof value === "string"))
				throw new TypeError("Invalid Trust Mark issuer configuration");
			if (allowed.length > 0 && !allowed.includes(this.issuer))
				throw new Error("Issuer is not authorized for this Trust Mark type");
		}
	}
	/** Replace detached local owner and issuer policy for subsequent service operations. */
	updatePolicy(
		owners: Readonly<Record<string, TrustMarkOwner>>,
		issuers?: Readonly<Record<string, readonly string[]>>,
	) {
		this.ownerPolicy = freezeSnapshot(structuredClone(owners));
		this.issuerPolicy = issuers ? freezeSnapshot(structuredClone(issuers)) : undefined;
		this.version++;
	}
	/** Replace the detached owner-delegation JWT map used for managed issuance. */
	async setDelegations(delegations: Readonly<Record<string, string>>): Promise<void> {
		if (
			!isJsonData(delegations) ||
			Array.isArray(delegations) ||
			Object.values(delegations).some((v) => typeof v !== "string")
		)
			throw new TypeError("Invalid Trust Mark delegations");
		this.delegations = freezeSnapshot(structuredClone(delegations));
		this.version++;
	}
	/**
	 * Assess stored issuance under current signatures, local revocation, expiry, and delegation
	 * policy.
	 */
	async eligibility(
		record: TrustMarkRecord,
		at = nowSeconds(this.config.options?.clock),
	): Promise<string> {
		const decoded = decodeEntityStatement(record.jwt);
		if (
			!decoded.ok ||
			String(decoded.value.payload.iss) !== this.issuer ||
			String(decoded.value.payload.sub) !== record.subject ||
			decoded.value.payload.trust_mark_type !== record.trustMarkType
		)
			return "invalid";
		if (decoded.value.payload.exp !== undefined && decoded.value.payload.exp <= at)
			return "expired";
		if (!record.active) return "revoked";
		if (!Number.isFinite(decoded.value.payload.iat) || decoded.value.payload.iat > at)
			return "invalid";
		const current = await this.config.keyProvider.getFederationKeySet();
		let keys = current.jwks;
		const kid = decoded.value.header.kid;
		if (typeof kid !== "string") return "invalid";
		if (!keys.keys.some((k) => k.kid === kid)) {
			const provider = this.config.keyProvider as Partial<FederationKeyLifecycleProvider>;
			if (!provider.getHistoricalFederationKeys) return "invalid";
			const selected = selectHistoricalVerificationKey(
				await provider.getHistoricalFederationKeys(),
				{ kid, validAt: decoded.value.payload.iat },
			);
			if (!selected.ok) return "invalid";
			keys = { keys: [selected.value] };
		}
		const checked = await validateTrustMark(
			record.jwt,
			{ [record.trustMarkType]: [this.issuer] },
			keys,
			{
				...this.config.options,
				clock: { now: () => at },
				clockSkewSeconds: 0,
				expectedSubject: record.subject,
				expectedTrustMarkType: record.trustMarkType,
				trustMarkOwners: this.owners(record.trustMarkType),
			},
		);
		if (!checked.ok) return "invalid";
		const now = nowSeconds(this.config.options?.clock);
		if ((checked.value.verificationExpiresAt ?? Infinity) <= now)
			return decoded.value.payload.exp !== undefined && decoded.value.payload.exp <= now
				? "expired"
				: "invalid";
		return "active";
	}
	private async eligible(
		store: Pick<TrustMarkStorage, "listCandidates">,
		filter: { trustMarkType?: string; subject?: EntityId },
		at: number,
	): Promise<TrustMarkRecord[]> {
		const records = await store.listCandidates({ issuer: this.issuer, ...filter });
		const valid: TrustMarkRecord[] = [];
		for (const record of records)
			if ((await this.eligibility(record, at)) === "active") valid.push(record);
		return valid.sort(
			(a, b) => b.issuedAt - a.issuedAt || (a.jwt < b.jwt ? 1 : a.jwt > b.jwt ? -1 : 0),
		);
	}
	/** Return detached, currently eligible records for the subject from one storage snapshot. */
	async listTrustMarksForSubject(subject: string): Promise<TrustMarkRecord[]> {
		const id = entityId(subject),
			at = nowSeconds(this.config.options?.clock);
		return this.config.storage.readSnapshot(async (snapshot) =>
			structuredClone(await this.eligible(snapshot.trustMarks, { subject: id }, at)),
		);
	}
	/** Return an eligible stored JWT for the subject and type, if one exists. */
	async getTrustMark(subject: string, type: string): Promise<string | undefined> {
		return (await this.listTrustMarksForSubject(subject)).find(
			(record) => record.trustMarkType === type,
		)?.jwt;
	}
	/** List distinct eligible subjects for a type, optionally restricted to one subject. */
	async listTrustMarkedEntities(type: string, subject?: string): Promise<string[]> {
		const filter = { trustMarkType: type, ...(subject ? { subject: entityId(subject) } : {}) };
		return this.config.storage.readSnapshot(async (snapshot) =>
			[
				...new Set(
					(
						await this.eligible(snapshot.trustMarks, filter, nowSeconds(this.config.options?.clock))
					).map((r) => r.subject),
				),
			].sort(),
		);
	}
	/** Revoke matching records issued by this service within a storage transaction. */
	async revokeTrustMark(type: string, subject: string): Promise<void> {
		const id = entityId(subject),
			at = nowSeconds(this.config.options?.clock);
		await this.config.storage.transaction((tx) => tx.trustMarks.revoke(type, id, at, this.issuer));
	}
	private assertReuse(record: TrustMarkRecord, requested: TrustMarkIssuanceOptions) {
		const decoded = decodeEntityStatement(record.jwt);
		if (!decoded.ok) throw new Error("Invalid stored Trust Mark");
		const p = decoded.value.payload as Record<string, unknown>;
		if (
			requested.ttlSeconds !== undefined &&
			(record.expiresAt === undefined ||
				record.expiresAt - record.issuedAt !== requested.ttlSeconds)
		)
			throw new Error("Requested lifetime conflicts with stored Trust Mark; use renewal: renew");
		if (requested.noExpiry !== undefined && requested.noExpiry !== (record.expiresAt === undefined))
			throw new Error("Requested expiry mode conflicts with stored Trust Mark; use renewal: renew");
		for (const [field, value] of [
			["logo_uri", requested.logoUri],
			["ref", requested.ref],
		] as const)
			if (value !== undefined && value !== p[field])
				throw new Error("Requested claims conflict with stored Trust Mark; use renewal: renew");
		if (requested.typ !== undefined && requested.typ !== decoded.value.header.typ)
			throw new Error("Requested profile conflicts with stored Trust Mark; use renewal: renew");
		for (const [field, value] of Object.entries(requested.additionalClaims ?? {}))
			if (!Object.hasOwn(p, field) || !sameJson(value, p[field]))
				throw new Error("Requested claims conflict with stored Trust Mark; use renewal: renew");
	}
	/**
	 * Authorize and store issuance. Reuse an eligible mark unless renewal requests a new JWT.
	 * Reject requests whose claims conflict with the mark being reused.
	 */
	async issueTrustMark(
		subject: string,
		type: string,
		requested: TrustMarkIssuanceOptions = {},
	): Promise<string> {
		const id = entityId(subject);
		this.authorize(type);
		if (!this.statusNotice && !this.config.statusEndpointPublished) {
			this.statusNotice = true;
			safeLogger(this.config.options?.logger)?.info(
				"Trust Mark Issuers SHOULD publish a federation_trust_mark_status_endpoint",
			);
		}
		validateIssuanceOptions(requested);
		const captured = structuredClone(requested);
		if (
			captured.renewal !== undefined &&
			captured.renewal !== "reuse" &&
			captured.renewal !== "renew"
		)
			throw new TypeError("Invalid renewal mode");
		if (captured.noExpiry && captured.ttlSeconds !== undefined)
			throw new TypeError("noExpiry and ttlSeconds conflict");
		const version = this.version;
		const reuse = async (store: Pick<TrustMarkStorage, "listCandidates">) => {
			if (captured.renewal === "renew") return undefined;
			const candidate = (
				await this.eligible(
					store,
					{ trustMarkType: type, subject: id },
					nowSeconds(this.config.options?.clock),
				)
			)[0];
			if (candidate) this.assertReuse(candidate, captured);
			return candidate;
		};
		const prior = await this.config.storage.transaction((tx) => reuse(tx.trustMarks));
		if (version !== this.version)
			throw new Error("Trust Mark policy changed during issuance; retry the operation");
		if (prior) return prior.jwt;
		const perType = Object.hasOwn(this.typeDefaults, type) ? this.typeDefaults[type] : undefined;
		const effective: TrustMarkIssuanceOptions = { ...this.defaults, ...perType, ...captured };
		// A selected lifetime mode replaces the lower-precedence mode as a whole.
		const lifetime =
			captured.noExpiry !== undefined || captured.ttlSeconds !== undefined
				? captured
				: perType?.noExpiry !== undefined || perType?.ttlSeconds !== undefined
					? perType
					: this.defaults;
		const now = nowSeconds(this.config.options?.clock);
		const keySet = await this.config.keyProvider.getFederationKeySet();
		const delegation = Object.hasOwn(this.delegations, type) ? this.delegations[type] : undefined;
		const signer = this.config.trustMarkSigner
			? await this.config.trustMarkSigner(
					Object.freeze({ issuer: this.issuer, subject: id, trustMarkType: type }),
				)
			: keySet.signer;
		const signing: SignTrustMarkOptions = {
			issuer: this.issuer,
			subject: id,
			trustMarkType: type,
			signer,
			clock: { now: () => now },
			...(lifetime.noExpiry
				? { noExpiry: true }
				: { ttlSeconds: lifetime.ttlSeconds ?? DEFAULT_DELEGATION_TTL_SECONDS }),
			...(effective.logoUri !== undefined ? { logoUri: effective.logoUri } : {}),
			...(effective.ref !== undefined ? { ref: effective.ref } : {}),
			...(effective.typ !== undefined ? { typ: effective.typ } : {}),
			...(effective.additionalClaims !== undefined
				? { additionalClaims: effective.additionalClaims }
				: {}),
			...(delegation !== undefined ? { delegation } : {}),
			...(this.config.options?.trustMarkProfiles
				? { trustMarkProfiles: this.config.options.trustMarkProfiles }
				: {}),
		};
		const jwt = await signTrustMark(signing);
		const checked = await validateTrustMark(jwt, { [type]: [this.issuer] }, keySet.jwks, {
			...this.config.options,
			expectedSubject: id,
			expectedTrustMarkType: type,
			trustMarkOwners: this.owners(type),
			clockSkewSeconds: 0,
		});
		if (!checked.ok) throw new Error(checked.error.description);
		const record: TrustMarkRecord = {
			trustMarkType: type,
			subject: id,
			jwt,
			issuedAt: checked.value.issuedAt,
			...(checked.value.expiresAt !== undefined ? { expiresAt: checked.value.expiresAt } : {}),
			active: true,
		};
		return this.config.storage.transaction(async (tx) => {
			if (version !== this.version)
				throw new Error("Trust Mark policy changed during issuance; retry the operation");
			const winner = await reuse(tx.trustMarks);
			if (winner) return winner.jwt;
			if ((await this.eligibility(record)) !== "active")
				throw new Error("Trust Mark is no longer eligible for issuance");
			const collision = await tx.trustMarks.getByJwt(jwt);
			if (collision && !collision.active)
				throw new Error(
					"Identical Trust Mark was revoked; advance the issuance time before renewing",
				);
			await tx.trustMarks.issue(record);
			return jwt;
		});
	}
	private async requestExtensions(
		kind: "status" | "list" | "retrieval",
		params: URLSearchParams,
		request: Request,
	): Promise<boolean> {
		const caller = authenticatedEndpointCaller(request);
		const context = freezeSnapshot({
			endpoint: kind,
			issuer: this.issuer,
			...(caller ? { caller } : {}),
			parameters: Object.fromEntries(
				[...new Set(params.keys())].map((name) => [name, params.getAll(name)]),
			),
		});
		for (const name of new Set(params.keys())) {
			const handler = this.extensions.get(name);
			if (!handler) continue;
			const result = await handler(Object.freeze(params.getAll(name)), context);
			if (result?.ok !== true) return false;
		}
		return true;
	}
	/** Handle a Trust Mark endpoint operation; hosting code supplies endpoint authentication. */
	async handleRequest(kind: "status" | "list" | "retrieval", request: Request): Promise<Response> {
		const methodError = requireMethod(request, kind === "status" ? "POST" : "GET");
		if (methodError) return methodError;
		try {
			let params: URLSearchParams;
			if (kind === "status") {
				const body = await readBodyWithLimit(request, DEFAULT_MAX_REQUEST_BODY_BYTES);
				if (!body.ok) return errorResponse(413, "invalid_request", "Request body too large");
				params = new URLSearchParams(body.text);
				const trustMark = params.get("trust_mark");
				if (params.getAll("trust_mark").length !== 1 || !trustMark)
					return errorResponse(400, "invalid_request", "Missing or repeated trust_mark");
				if (!(await this.requestExtensions(kind, params, request)))
					return errorResponse(
						400,
						"invalid_request",
						"Trust Mark request extension rejected the request",
					);
				const response = await this.statusResponse(trustMark);
				return response
					? jwtResponse(response, MediaType.TrustMarkStatusResponse)
					: errorResponse(404, "not_found", "Trust mark not found");
			}
			params = new URL(request.url).searchParams;
			const type = params.get("trust_mark_type"),
				subject = params.get("sub");
			if (!type || params.getAll("trust_mark_type").length !== 1 || params.getAll("sub").length > 1)
				return errorResponse(400, "invalid_request", "Missing or repeated Trust Mark selector");
			if (subject !== null) {
				try {
					entityId(subject);
				} catch {
					return errorResponse(400, "invalid_request", "Invalid sub");
				}
			}
			if (!(await this.requestExtensions(kind, params, request)))
				return errorResponse(
					400,
					"invalid_request",
					"Trust Mark request extension rejected the request",
				);
			if (kind === "list")
				return jsonResponse(await this.listTrustMarkedEntities(type, subject ?? undefined));
			if (!subject) return errorResponse(400, "invalid_request", "Missing sub");
			const jwt = await this.getTrustMark(subject, type);
			return jwt
				? jwtResponse(jwt, MediaType.TrustMark)
				: errorResponse(404, "not_found", "Trust mark not found");
		} catch {
			return errorResponse(500, "server_error", "Trust Mark operation failed");
		}
	}
	/** Assess current status without signing; unknown instances have no assessment. */
	async assessTrustMarkStatus(jwt: string): Promise<TrustMarkStatusAssessment | undefined> {
		const version = this.version;
		const record = await this.config.storage.readSnapshot((tx) => tx.trustMarks.getByJwt(jwt));
		const decoded = decodeEntityStatement(jwt);
		if (!record || !decoded.ok || String(decoded.value.payload.iss) !== this.issuer)
			return undefined;
		const baseStatus = await this.eligibility(record);
		const custom = this.config.trustMarkStatusPolicy
			? await this.config.trustMarkStatusPolicy(
					freezeSnapshot({ baseStatus, record: structuredClone(record) }),
				)
			: { status: baseStatus };
		if (
			!custom ||
			typeof custom.status !== "string" ||
			!custom.status ||
			(baseStatus !== "active" && custom.status === "active")
		)
			throw new Error("Invalid Trust Mark status policy result");
		const payload: TrustMarkStatusResponsePayload = {
			iss: EntityIdSchema.parse(this.issuer),
			iat: nowSeconds(this.config.options?.clock),
			trust_mark: jwt,
			status: custom.status,
		};
		if (custom.additionalClaims !== undefined) {
			if (!isJsonData(custom.additionalClaims) || Array.isArray(custom.additionalClaims))
				throw new TypeError("Status claims must be JSON object data");
			const reserved = new Set(["iss", "iat", "trust_mark", "status", "alg", "kid", "typ", "crit"]);
			for (const [name, value] of Object.entries(custom.additionalClaims)) {
				if (reserved.has(name)) throw new TypeError("Reserved status claim");
				setOwn(payload, name, structuredClone(value));
			}
		}
		const refreshed = await this.config.storage.readSnapshot((tx) => tx.trustMarks.getByJwt(jwt));
		if (!refreshed) return undefined;
		const currentStatus = await this.eligibility(refreshed);
		if (version !== this.version)
			throw new Error("Trust Mark policy changed during status assessment");
		if (payload.status === "active" && currentStatus !== "active") payload.status = currentStatus;
		payload.iat = nowSeconds(this.config.options?.clock);
		const delegation =
			typeof decoded.value.payload.delegation === "string"
				? decodeEntityStatement(decoded.value.payload.delegation)
				: undefined;
		const issuerProof = this.config.issuerEvidence?.find(
			(evidence) =>
				evidence.issuer === this.issuer &&
				evidence.kind === "federation" &&
				evidence.trustMarkType === record.trustMarkType,
		);
		const deadline = Math.min(
			issuerProof?.kind === "federation" ? issuerProof.expiresAt : Infinity,
			typeof payload.exp === "number" ? payload.exp : Infinity,
			decoded.value.payload.exp ?? Infinity,
			delegation?.ok ? (delegation.value.payload.exp ?? Infinity) : Infinity,
		);
		const assessment = freezeSnapshot({
			payload,
			...(payload.status === "active" && Number.isFinite(deadline)
				? { verificationExpiresAt: deadline }
				: {}),
		});
		await this.assertCurrentStatus(assessment, version);
		return assessment;
	}
	private async assertCurrentStatus(
		assessment: TrustMarkStatusAssessment,
		version: number,
	): Promise<void> {
		if (assessment.payload.status === "active") {
			const record = await this.config.storage.readSnapshot((tx) =>
				tx.trustMarks.getByJwt(assessment.payload.trust_mark),
			);
			if (!record || (await this.eligibility(record)) !== "active")
				throw new Error("Trust Mark status assessment is no longer active");
			// Key/profile checks may await host code. Finish with a fresh revocation and time check.
			const latest = await this.config.storage.readSnapshot((tx) =>
				tx.trustMarks.getByJwt(assessment.payload.trust_mark),
			);
			if (
				!latest?.active ||
				(assessment.verificationExpiresAt ?? Infinity) <= nowSeconds(this.config.options?.clock)
			)
				throw new Error("Trust Mark status assessment is no longer active");
		}
		if (version !== this.version)
			throw new Error("Trust Mark policy changed during status assessment");
	}
	/** Sign a status assessment after applying eligibility and the configured custom status policy. */
	async statusResponse(jwt: string): Promise<string | undefined> {
		const version = this.version;
		const assessment = await this.assessTrustMarkStatus(jwt);
		if (!assessment) return undefined;
		const keySet = await this.config.keyProvider.getFederationKeySet();
		await this.assertCurrentStatus(assessment, version);
		const response = await signEntityStatement(
			{ ...assessment.payload, iat: nowSeconds(this.config.options?.clock) },
			keySet.signer,
			{ typ: JwtTyp.TrustMarkStatusResponse },
		);
		await this.assertCurrentStatus(assessment, version);
		return response;
	}
}
