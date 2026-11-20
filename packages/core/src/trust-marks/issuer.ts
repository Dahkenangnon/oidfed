import { federationSigningOptions } from "../crypto-context.js";
import { cloneData } from "../data-copy.js";
import { federationEntry } from "../federation-keys.js";

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
import { selectHistoricalVerificationKey } from "../federation-api/historical-keys.js";
import {
	errorResponse,
	jsonResponse,
	jwtResponse,
	readBodyWithLimit,
	requireMethod,
} from "../http.js";
import { signEntityStatement } from "../jose/sign.js";
import { decodeEntityStatement } from "../jose/verify.js";
import { safeLogger } from "../logging.js";
import type { TrustMarkStatusResponsePayload } from "../schemas/endpoints.js";
import { EntityIdSchema } from "../schemas/entity-id.js";
import type { TrustMarkOwner } from "../schemas/trust-mark.js";
import {
	assertStorageCapabilities,
	assertStorageView,
	describeStorageRequirements,
	storageSnapshot,
	storageTransaction,
} from "../storage/capabilities.js";
import type { FederationStorage, ReadSnapshotView } from "../storage/contracts.js";
import type { TrustMarkReadStore, TrustMarkRecord } from "../storage/trust-mark.js";
import { assertPositiveTtlSeconds } from "../ttl.js";
import type { CryptoContext } from "../types.js";
import { type EntityId, entityId, type FederationOptions, nowSeconds } from "../types.js";
import { type TrustMarkIssuerContext, trustMarkIssuerContext } from "./evidence.js";
import { type SignTrustMarkOptions, signTrustMark, type TrustMarkLifetime } from "./sign.js";
import { validateTrustMark } from "./validate.js";

type CandidateFilter = { trustMarkType?: string; subject?: EntityId };
type Eligibility = { readonly status: string; readonly expiresAt?: number };

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
	readonly storage: FederationStorage;
	readonly authentication?: Omit<EndpointAuthenticationConfig, "receiverEntityId" | "methods">;
	readonly defaults?: TrustMarkIssuanceOptions;
	readonly trustMarkDefaults?: Readonly<Record<string, TrustMarkIssuanceOptions>>;
	readonly delegations?: Readonly<Record<string, string>>;
	/** Independent issuer trust supplies owner keys for delegated issuance. */
	readonly issuerEvidence?: readonly TrustMarkIssuerContext[];
	readonly trustMarkStatusPolicy?: TrustMarkStatusPolicy;
}
export interface TrustMarkIssuerServiceOptions extends TrustMarkIssuerConfig {
	readonly issuer: string;
	readonly statusEndpointPublished?: boolean;
	readonly crypto: CryptoContext;
	readonly options: FederationOptions;
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
		assertStorageCapabilities(
			config.storage,
			describeStorageRequirements("trustMarkRead"),
			`Trust Mark issuer ${this.issuer}`,
		);
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
		this.ownerPolicy = freezeSnapshot(cloneData(config.trustMarkOwners ?? {}));
		this.issuerPolicy = config.trustMarkIssuers
			? freezeSnapshot(cloneData(config.trustMarkIssuers))
			: undefined;
		this.config = {
			...config,
			...(config.issuerEvidence
				? {
						issuerEvidence: config.issuerEvidence.map((evidence) =>
							evidence.kind === "federation" ? evidence : freezeSnapshot(cloneData(evidence)),
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
		this.defaults = freezeSnapshot(cloneData(config.defaults ?? {}));
		this.typeDefaults = freezeSnapshot(cloneData(config.trustMarkDefaults ?? {}));
		if (Object.values(config.delegations ?? {}).some((value) => typeof value !== "string"))
			throw new TypeError("Invalid Trust Mark delegation configuration");
		this.delegations = freezeSnapshot(cloneData(config.delegations ?? {}));
	}
	private ownerContext(type: string): {
		owners: Record<string, TrustMarkOwner>;
		expiresAt?: number;
	} {
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
			return trusted.value;
		}
		return { owners: cloneData(this.ownerPolicy) };
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
		this.ownerPolicy = freezeSnapshot(cloneData(owners));
		this.issuerPolicy = issuers ? freezeSnapshot(cloneData(issuers)) : undefined;
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
		this.delegations = freezeSnapshot(cloneData(delegations));
		this.version++;
	}
	/**
	 * Assess stored issuance under current signatures, local revocation, expiry, and delegation
	 * policy.
	 */
	async eligibility(record: TrustMarkRecord, at?: number): Promise<string> {
		return (await this.evaluateEligibility(record, at)).status;
	}
	private async evaluateEligibility(
		record: TrustMarkRecord,
		at = nowSeconds(this.config.options?.clock),
	): Promise<Eligibility> {
		const decoded = decodeEntityStatement(record.jwt, this.config.options);
		if (
			!decoded.ok ||
			String(decoded.value.payload.iss) !== this.issuer ||
			String(decoded.value.payload.sub) !== record.subject ||
			decoded.value.payload.trust_mark_type !== record.trustMarkType
		)
			return { status: "invalid" };
		if (decoded.value.payload.exp !== undefined && decoded.value.payload.exp <= at)
			return { status: "expired" };
		if (!record.active) return { status: "revoked" };
		if (
			!Number.isFinite(decoded.value.payload.iat) ||
			decoded.value.payload.iat > at ||
			!Number.isFinite(record.issuedAt) ||
			(record.expiresAt !== undefined && !Number.isFinite(record.expiresAt))
		)
			return { status: "invalid" };
		let ownerContext: ReturnType<TrustMarkIssuerService["ownerContext"]>;
		try {
			this.authorize(record.trustMarkType);
			ownerContext = this.ownerContext(record.trustMarkType);
		} catch {
			return { status: "invalid" };
		}
		const current = await federationEntry(this.config.crypto, {
			issuer: this.issuer,
			subject: record.subject,
			trustMarkType: record.trustMarkType,
		});
		let keys = current.publishedJwks;
		const kid = decoded.value.header.kid;
		if (typeof kid !== "string") return { status: "invalid" };
		if (!keys.keys.some((k) => k.kid === kid)) {
			const provider = this.config.crypto.history;
			if (!provider) return { status: "invalid" };
			const selected = selectHistoricalVerificationKey(await provider.getHistoricalKeys(), {
				kid,
				validAt: decoded.value.payload.iat,
			});
			if (!selected.ok) return { status: "invalid" };
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
				trustMarkOwners: ownerContext.owners,
			},
		);
		if (!checked.ok) return { status: "invalid" };
		const now = nowSeconds(this.config.options?.clock);
		const deadline = Math.min(
			checked.value.verificationExpiresAt ?? Infinity,
			ownerContext.expiresAt ?? Infinity,
		);
		if (deadline <= now)
			return decoded.value.payload.exp !== undefined && decoded.value.payload.exp <= now
				? { status: "expired" }
				: { status: "invalid" };
		return { status: "active", expiresAt: deadline };
	}
	private read<T>(operation: (store: TrustMarkReadStore) => Promise<T>): Promise<T> {
		return storageSnapshot(
			this.config.storage,
			(view: ReadSnapshotView) => {
				assertStorageView(view, ["trustMark:read"], "Trust Mark read");
				return operation(view.trustMark);
			},
			this.config.options,
		);
	}
	private async eligible(
		records: readonly TrustMarkRecord[],
		at: number,
	): Promise<{ record: TrustMarkRecord; expiresAt: number }[]> {
		const valid: { record: TrustMarkRecord; expiresAt: number }[] = [];
		for (const record of records) {
			const eligibility = await this.evaluateEligibility(record, at);
			if (eligibility.status === "active")
				valid.push({ record, expiresAt: eligibility.expiresAt ?? Infinity });
		}
		const now = nowSeconds(this.config.options.clock);
		return valid
			.filter((mark) => mark.expiresAt > now)
			.sort(
				({ record: a }, { record: b }) =>
					b.issuedAt - a.issuedAt || (a.jwt < b.jwt ? 1 : a.jwt > b.jwt ? -1 : 0),
			);
	}
	private async eligibleCandidates(filter: CandidateFilter): Promise<TrustMarkRecord[]> {
		const records = await this.read((store) =>
			store.candidates({ issuer: this.issuer, ...filter }),
		);
		return (await this.eligible(records, nowSeconds(this.config.options.clock))).map(
			({ record }) => record,
		);
	}
	/** Return detached, currently eligible records for the subject from one storage snapshot. */
	async listTrustMarksForSubject(subject: string): Promise<TrustMarkRecord[]> {
		return this.eligibleCandidates({ subject: entityId(subject) });
	}
	/** Return an eligible stored JWT for the subject and type, if one exists. */
	async getTrustMark(subject: string, type: string): Promise<string | undefined> {
		return (await this.eligibleCandidates({ subject: entityId(subject), trustMarkType: type }))[0]
			?.jwt;
	}
	/** List distinct eligible subjects for a type, optionally restricted to one subject. */
	async listTrustMarkedEntities(type: string, subject?: string): Promise<string[]> {
		const filter = { trustMarkType: type, ...(subject ? { subject: entityId(subject) } : {}) };
		return [
			...new Set((await this.eligibleCandidates(filter)).map((record) => record.subject)),
		].sort();
	}
	/** Revoke matching records issued by this service within a storage transaction. */
	async revokeTrustMark(type: string, subject: string): Promise<void> {
		const id = entityId(subject);
		const at = nowSeconds(this.config.options.clock);
		assertStorageCapabilities(
			this.config.storage,
			describeStorageRequirements("trustMarkWrite"),
			"Revoke Trust Mark",
		);
		await storageTransaction(
			this.config.storage,
			(tx) => {
				assertStorageView(tx, ["trustMark:write"], "Revoke Trust Mark");
				return tx.trustMark.revoke(type, id, at, this.issuer);
			},
			this.config.options,
		);
	}

	private assertReuse(record: TrustMarkRecord, requested: TrustMarkIssuanceOptions) {
		const decoded = decodeEntityStatement(record.jwt, this.config.options);
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
		const captured = cloneData(requested);
		if (
			captured.renewal !== undefined &&
			captured.renewal !== "reuse" &&
			captured.renewal !== "renew"
		)
			throw new TypeError("Invalid renewal mode");
		if (captured.noExpiry && captured.ttlSeconds !== undefined)
			throw new TypeError("noExpiry and ttlSeconds conflict");
		assertStorageCapabilities(
			this.config.storage,
			describeStorageRequirements("trustMarkWrite"),
			"Issue Trust Mark",
		);
		const version = this.version;
		const filter = { issuer: this.issuer, trustMarkType: type, subject: id };
		const readCandidates = () =>
			this.read(async (store) => ({
				revision: await store.revision(),
				records: captured.renewal === "renew" ? [] : await store.candidates(filter),
			}));
		const assertPolicy = () => {
			if (version !== this.version)
				throw new Error("Trust Mark policy changed during issuance; retry the operation");
		};
		let signed: TrustMarkRecord | undefined;
		for (let attempt = 0; attempt < 3; attempt++) {
			const { revision, records } = await readCandidates();
			if (typeof revision !== "string" || !revision)
				throw new TypeError("Trust Mark storage returned an invalid revision");
			const now = nowSeconds(this.config.options.clock);
			const winner = (await this.eligible(records, now))[0];
			assertPolicy();
			if (!winner && !signed) signed = await this.signRecord(id, type, captured);
			const proof =
				winner ??
				(signed
					? {
							record: signed,
							expiresAt: (await this.evaluateEligibility(signed)).expiresAt ?? -Infinity,
						}
					: undefined);
			assertPolicy();
			if (!proof || (!winner && proof.expiresAt <= nowSeconds(this.config.options.clock)))
				throw new Error("Trust Mark is no longer eligible for issuance");
			const completed = await storageTransaction(
				this.config.storage,
				async (tx) => {
					assertStorageView(tx, ["trustMark:write"], "Issue Trust Mark");
					if ((await tx.trustMark.checkRevision(revision)) !== true) return false;
					assertPolicy();
					if (proof.expiresAt <= nowSeconds(this.config.options.clock)) return false;
					if (winner) {
						this.assertReuse(proof.record, captured);
						return true;
					}
					const store = tx.trustMark;
					const collision = await store.status(proof.record.jwt);
					assertPolicy();
					if (proof.expiresAt <= nowSeconds(this.config.options.clock)) return false;
					if (collision && !collision.active)
						throw new Error(
							"Identical Trust Mark was revoked; advance the issuance time before renewing",
						);
					await store.issue(proof.record);
					assertPolicy();
					if (proof.expiresAt <= nowSeconds(this.config.options.clock))
						throw new Error("Trust Mark expired during issuance");
					return true;
				},
				this.config.options,
			);
			if (completed) {
				assertPolicy();
				if (proof.expiresAt <= nowSeconds(this.config.options.clock))
					throw new Error("Trust Mark expired before issuance completed");
				return proof.record.jwt;
			}
		}
		throw new Error("Trust Mark storage changed during issuance; retry the operation");
	}
	private async signRecord(
		id: EntityId,
		type: string,
		captured: TrustMarkIssuanceOptions,
	): Promise<TrustMarkRecord> {
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
		const keySet = await federationEntry(this.config.crypto, {
			issuer: this.issuer,
			subject: id,
			trustMarkType: type,
		});
		const delegation = Object.hasOwn(this.delegations, type) ? this.delegations[type] : undefined;
		const signer = keySet;
		const signing: SignTrustMarkOptions = {
			maxCompactBytes: this.config.options.maxCompactBytes,
			algorithmRegistry: this.config.options.algorithmRegistry,
			allowedFederationAlgorithms: this.config.options.allowedFederationAlgorithms,
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
		const checked = await validateTrustMark(jwt, { [type]: [this.issuer] }, keySet.publishedJwks, {
			...this.config.options,
			expectedSubject: id,
			expectedTrustMarkType: type,
			trustMarkOwners: this.ownerContext(type).owners,
			clockSkewSeconds: 0,
		});
		if (!checked.ok) throw new Error(checked.error.description);
		return {
			trustMarkType: type,
			subject: id,
			jwt,
			issuedAt: checked.value.issuedAt,
			...(checked.value.expiresAt !== undefined ? { expiresAt: checked.value.expiresAt } : {}),
			active: true,
		};
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
		return (await this.assessStoredStatus(jwt))?.assessment;
	}
	private async assessStoredStatus(jwt: string) {
		const version = this.version;
		const record = await this.read((store) => store.status(jwt));
		const decoded = decodeEntityStatement(jwt, this.config.options);
		if (!record || !decoded.ok || String(decoded.value.payload.iss) !== this.issuer)
			return undefined;
		const baseStatus = await this.eligibility(record);
		const custom = this.config.trustMarkStatusPolicy
			? await this.config.trustMarkStatusPolicy(
					freezeSnapshot({ baseStatus, record: cloneData(record) }),
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
				setOwn(payload, name, cloneData(value));
			}
		}
		const refreshed = await this.read((store) => store.status(jwt));
		if (!refreshed) return undefined;
		const currentStatus = await this.eligibility(refreshed);
		if (version !== this.version)
			throw new Error("Trust Mark policy changed during status assessment");
		if (payload.status === "active" && currentStatus !== "active") payload.status = currentStatus;
		payload.iat = nowSeconds(this.config.options?.clock);
		const delegation =
			typeof decoded.value.payload.delegation === "string"
				? decodeEntityStatement(decoded.value.payload.delegation, this.config.options)
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
		return { assessment, subject: record.subject, trustMarkType: record.trustMarkType };
	}
	private async assertCurrentStatus(
		assessment: TrustMarkStatusAssessment,
		version: number,
	): Promise<void> {
		if (assessment.payload.status === "active") {
			const record = await this.read((store) => store.status(assessment.payload.trust_mark));
			if (!record || (await this.eligibility(record)) !== "active")
				throw new Error("Trust Mark status assessment is no longer active");
			// Key/profile checks may await host code. Finish with a fresh revocation and time check.
			const latest = await this.read((store) => store.status(assessment.payload.trust_mark));
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
		const stored = await this.assessStoredStatus(jwt);
		if (!stored) return undefined;
		const { assessment, subject, trustMarkType } = stored;
		const keySet = await federationEntry(this.config.crypto, {
			issuer: this.issuer,
			subject,
			trustMarkType,
		});
		await this.assertCurrentStatus(assessment, version);
		const response = await signEntityStatement(
			{ ...assessment.payload, iat: nowSeconds(this.config.options?.clock) },
			keySet,
			{ ...federationSigningOptions(this.config.options), typ: JwtTyp.TrustMarkStatusResponse },
		);
		await this.assertCurrentStatus(assessment, version);
		return response;
	}
}
