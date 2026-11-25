import { utf8Encode } from "@oidfed/crypto";
import { randomUuid } from "../crypto-runtime.js";
import { cloneData } from "../data-copy.js";
import { InvalidStorageRecordError } from "../storage/errors.js";
import {
	collectionReadSchema,
	EntityCollectionCursorSchema,
	parseStorageRecord,
} from "../storage/record-schemas.js";
/** Collection refresh coordination, snapshot queries, and HTTP endpoint hosting. */

import { waitForOperation } from "../async-operation.js";
import { callSynchronous, freezeSnapshot } from "../callbacks.js";
import {
	DEFAULT_HTTP_TIMEOUT_MS,
	DEFAULT_MAX_REQUEST_BODY_BYTES,
	DEFAULT_MAX_RESOLUTION_STEPS,
	DEFAULT_MAX_RESPONSE_BYTES,
	FederationErrorCode,
} from "../constants.js";
import {
	endpointAuthenticationErrorResponse,
	endpointCredentialParameterNames,
	validateEndpointAuthentication,
} from "../endpoint-authentication.js";
import { authorizeFederationEndpoint } from "../endpoint-authorization.js";
import {
	COLLECTION_UNORDERED_PARAMETERS,
	endpointParameterValuesMatch,
} from "../endpoint-parameters.js";
import { err, ok, type Result } from "../errors.js";
import { readResponseBody } from "../http/response-body.js";
import { errorResponse, jsonResponse, parseContentTypeHeader, toPublicError } from "../http.js";
import { splitInformationalClaim } from "../language-tags.js";
import { safeLogger } from "../logging.js";
import {
	COLLECTION_INFO_CLAIMS,
	type EntityCollectionRequestParams,
	EntityCollectionRequestSchema,
	type EntityCollectionResponse,
} from "../schemas/entity-collection.js";
import { assertStorageCapabilities } from "../storage/capabilities.js";
import type { EntityCollectionStore } from "../storage/collection.js";
import { EntityCollectionCursorCapacityError } from "../storage/collection-memory.js";
import { type EntityId, entityId, isValidEntityId, nowSeconds } from "../types.js";
import { authenticateCollectionRequest } from "./auth.js";
import {
	COLLECTION_PARAMETERS,
	collectionContext,
	collectionText,
	parseCollectionParams,
	projectCollectionEntity,
} from "./protocol.js";
import { buildCollectionSnapshot } from "./refresh.js";
import type {
	CollectionRefreshOptions,
	CollectionRefreshResult,
	EntityCollectionConfig,
} from "./types.js";

/** Shared unsigned collection service for federation entities and independent providers. */
export class EntityCollectionService {
	readonly store: EntityCollectionStore;
	private readonly config: EntityCollectionConfig;
	private readonly snapshotSchema: ReturnType<typeof collectionReadSchema>;
	private readonly fixedQuery: URLSearchParams;
	private readonly refreshes = new Map<string, Promise<Result<CollectionRefreshResult>>>();
	/**
	 * Validate collection limits and authentication before retaining configuration and storage
	 * dependencies.
	 */
	constructor(config: EntityCollectionConfig) {
		if (config.queryMatcher !== undefined && typeof config.queryMatcher !== "function")
			throw new TypeError("Collection queryMatcher must be a function");
		for (const values of [
			config.entityClaims,
			config.infoClaims,
			config.defaultEntityClaims,
			config.defaultInfoClaims,
		])
			if (
				values !== undefined &&
				(!Array.isArray(values) ||
					!values.every((value) => typeof value === "string" && value.length > 0))
			)
				throw new Error("Collection claim declarations must be nonempty strings");
		const infoNames = new Set<string>([...COLLECTION_INFO_CLAIMS, ...(config.infoClaims ?? [])]);
		const entityNames = new Set([
			"entity_id",
			"entity_types",
			"entity_infos",
			"trust_marks",
			...(config.entityClaims ?? []),
		]);
		if (
			config.defaultEntityClaims?.some((name) => !entityNames.has(name)) ||
			config.defaultInfoClaims?.some((name) => {
				const parsed = splitInformationalClaim(name, infoNames);
				return parsed.malformed || !infoNames.has(parsed.base);
			})
		)
			throw new Error("Default collection selectors must name supported claims");
		config = {
			...config,
			...(config.entityClaims ? { entityClaims: [...config.entityClaims] } : {}),
			...(config.infoClaims ? { infoClaims: [...config.infoClaims] } : {}),
			...(config.defaultEntityClaims
				? { defaultEntityClaims: [...config.defaultEntityClaims] }
				: {}),
			...(config.defaultInfoClaims ? { defaultInfoClaims: [...config.defaultInfoClaims] } : {}),
		};

		for (const value of [
			config.maxPageSize ?? 100,
			config.cursorTtlSeconds ?? 900,
			config.maxEntities ?? 10000,
			config.options?.maxConcurrentFetches ?? 6,
			config.options?.maxTotalFetches ?? 1000,
			config.options?.maxChainDepth ?? 8,
			config.options?.maxResolutionSteps ?? DEFAULT_MAX_RESOLUTION_STEPS,
			config.options?.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES,
			config.options?.httpTimeoutMs ?? DEFAULT_HTTP_TIMEOUT_MS,
		])
			if (!Number.isSafeInteger(value) || value <= 0)
				throw new Error("Collection limits must be positive safe integers");
		for (const anchor of config.trustAnchors.keys()) entityId(anchor);
		if (config.responder) entityId(config.responder.entityId);
		if (config.endpoint !== undefined) {
			const url = new URL(config.endpoint);
			if (url.protocol !== "https:" || url.href.includes("#") || url.username || url.password)
				throw new Error("Collection endpoint must use HTTPS without credentials or fragments");
			this.fixedQuery = url.searchParams;
		} else this.fixedQuery = new URLSearchParams();
		const auth = config.authentication;
		if (config.options.authorizeEndpointRequest && !config.responder && !auth?.receiverEntityId)
			throw new TypeError("Collection authorization requires a receiver Entity Identifier");
		if (
			config.responder &&
			auth?.receiverEntityId &&
			config.responder.entityId !== auth.receiverEntityId
		)
			throw new Error("Collection assertion audience must match the responder Entity Identifier");
		if (
			auth &&
			(!auth.methods.length ||
				auth.methods.some(
					(method) =>
						method !== "none" &&
						method !== "private_key_jwt" &&
						!Object.hasOwn(auth.extensions?.methods ?? {}, method),
				))
		)
			throw new Error("Unsupported collection authentication method");
		if (
			auth?.methods.includes("private_key_jwt") &&
			(!auth.receiverEntityId ||
				!isValidEntityId(auth.receiverEntityId) ||
				!auth.getClientFederationJwks)
		)
			throw new Error(
				"Collection authentication needs a receiver identity and trusted client key provider",
			);
		if (
			auth?.methods.some((method) => method !== "none") &&
			(!auth.receiverEntityId || !isValidEntityId(auth.receiverEntityId))
		)
			throw new Error("Collection authentication requires a receiver Entity Identifier");
		this.config = {
			...config,
			...(!config.responder && auth?.receiverEntityId
				? { responder: { entityId: auth.receiverEntityId, isTrustAnchor: false } }
				: {}),
			trustAnchors: new Map(config.trustAnchors),
		};
		if (this.config.authentication) {
			const configured = this.config.authentication;
			const captured = validateEndpointAuthentication(
				{
					...configured,
					receiverEntityId: configured.receiverEntityId ?? "https://collection.invalid",
				},
				config.options.storage,
				config.options,
				"Entity Collection endpoint",
			);
			this.config.authentication = {
				...configured,
				...(captured.extensions ? { extensions: captured.extensions } : {}),
				methods: captured.methods,
				...(captured.allowedAlgorithms ? { allowedAlgorithms: captured.allowedAlgorithms } : {}),
				...(captured.advertisedAlgorithms
					? { advertisedAlgorithms: captured.advertisedAlgorithms }
					: {}),
			};
		}
		const storage = config.options.storage;
		assertStorageCapabilities(storage, ["entityCollection"], "Entity Collection");
		this.store = storage.entityCollection;
		this.snapshotSchema = collectionReadSchema(this.config.infoClaims, this.config.options);
	}

	/**
	 * Build and publish a snapshot, queuing refreshes for the same anchor.
	 * Cancellation releases the caller while later refreshes remain queued in order.
	 */
	async refresh(
		anchor: EntityId,
		options?: CollectionRefreshOptions,
	): Promise<Result<CollectionRefreshResult>> {
		const signals = [options?.signal, this.config.options?.signal];
		const cancelled = () =>
			err({
				code: FederationErrorCode.TemporarilyUnavailable,
				description: "Collection refresh cancelled",
			});
		if (signals.some((signal) => signal?.aborted)) return cancelled();
		const previous = this.refreshes.get(anchor);
		const run = (async () => {
			if (previous !== undefined) await previous;
			if (signals.some((signal) => signal?.aborted)) return cancelled();
			return this.performRefresh(anchor, options);
		})().catch((cause: unknown) =>
			err({
				code: FederationErrorCode.TemporarilyUnavailable,
				description: "Collection refresh could not be completed",
				cause,
			}),
		);
		this.refreshes.set(anchor, run);
		// A cancelled caller must not remove the serialization barrier for later refreshes.
		void run.then(() => {
			if (this.refreshes.get(anchor) === run) this.refreshes.delete(anchor);
		});
		try {
			return await waitForOperation(run, signals);
		} catch {
			return cancelled();
		}
	}
	private async performRefresh(
		anchor: EntityId,
		options?: CollectionRefreshOptions,
	): Promise<Result<CollectionRefreshResult>> {
		const built = await buildCollectionSnapshot(anchor, this.config, options?.signal);
		if (!built.ok) return built;
		try {
			if (options?.signal?.aborted || this.config.options?.signal?.aborted)
				return err({
					code: FederationErrorCode.TemporarilyUnavailable,
					description: "Collection refresh cancelled",
				});
			await this.store.publish(
				parseStorageRecord(this.snapshotSchema, built.value, "collectionSnapshot", "publish"),
			);
			return ok({
				snapshotId: built.value.id,
				lastUpdated: built.value.lastUpdated,
				entityCount: built.value.entries.length,
			});
		} catch (cause) {
			safeLogger(this.config.options?.logger)?.error("Collection snapshot publication failed");
			return err({
				code: FederationErrorCode.ServerError,
				description: "Collection publication failed",
				cause,
			});
		}
	}

	/**
	 * Query published snapshots and return a Result error for invalid selectors. This operation uses
	 * stored data.
	 */
	async query(
		params: EntityCollectionRequestParams = {},
	): Promise<Result<EntityCollectionResponse>> {
		const parsed = EntityCollectionRequestSchema.safeParse(params);
		if (!parsed.success)
			return err({
				code: FederationErrorCode.InvalidRequest,
				description: "Invalid collection request parameters",
			});
		const request = {
			...parsed.data,
			...(parsed.data.entityClaims === undefined && this.config.defaultEntityClaims !== undefined
				? { entityClaims: [...this.config.defaultEntityClaims] }
				: {}),
			...(parsed.data.infoClaims === undefined && this.config.defaultInfoClaims !== undefined
				? { infoClaims: [...this.config.defaultInfoClaims] }
				: {}),
		};
		const supportedInfoClaims = new Set<string>([
			...COLLECTION_INFO_CLAIMS,
			...(this.config.infoClaims ?? []),
		]);
		for (const [claims, supported, localized] of [
			[
				request.entityClaims,
				[
					"entity_id",
					"entity_types",
					"entity_infos",
					"trust_marks",
					...(this.config.entityClaims ?? []),
				],
				false,
			],
			[request.infoClaims, [...COLLECTION_INFO_CLAIMS, ...(this.config.infoClaims ?? [])], true],
		] as const)
			for (const claim of claims ?? []) {
				const parsed = localized
					? splitInformationalClaim(claim, supportedInfoClaims)
					: { base: claim };
				if (parsed.malformed || !supported.includes(parsed.base))
					return err({
						code: FederationErrorCode.UnsupportedClaim,
						description: `Unsupported claim: ${claim}`,
					});
			}
		let anchor: EntityId | undefined =
			request.trustAnchor === undefined ? undefined : entityId(request.trustAnchor);
		if (anchor === undefined) {
			if (!this.config.responder)
				return err({
					code: FederationErrorCode.InvalidRequest,
					description: "trust_anchor is required when the responder has no Entity Identifier",
				});
			// Draft 01 §3.3.1 explicitly requires an empty response for this case.
			if (!this.config.responder.isTrustAnchor) return ok({ entities: [] });
			anchor = this.config.responder.entityId;
		}
		if (!this.config.trustAnchors.has(anchor))
			return err({
				code: FederationErrorCode.InvalidTrustAnchor,
				description: "Unsupported collection Trust Anchor",
			});
		const effective = { ...request, trustAnchor: anchor };
		const context = collectionContext(effective);
		const now = nowSeconds(this.config.options?.clock);
		try {
			const rawCursor =
				request.from === undefined ? undefined : await this.store.cursor(request.from);
			const cursor =
				rawCursor === undefined
					? undefined
					: parseStorageRecord(EntityCollectionCursorSchema, rawCursor, "collectionCursor", "read");
			if (
				request.from !== undefined &&
				(!cursor ||
					cursor.context !== context ||
					cursor.trustAnchor !== anchor ||
					cursor.expiresAt <= now)
			)
				return err({
					code: FederationErrorCode.PageNotFound,
					description: "Unknown or expired collection cursor",
				});
			const rawSnapshot = cursor
				? await this.store.snapshot(cursor.snapshotId)
				: await this.store.current(anchor);
			if (rawSnapshot === undefined)
				return err({
					code: cursor
						? FederationErrorCode.PageNotFound
						: FederationErrorCode.TemporarilyUnavailable,
					description: "Collection snapshot is unavailable",
				});
			const snapshot = parseStorageRecord(
				this.snapshotSchema,
				rawSnapshot,
				"collectionSnapshot",
				"read",
			);
			if (cursor && (snapshot.id !== cursor.snapshotId || snapshot.trustAnchor !== anchor))
				return err({
					code: FederationErrorCode.PageNotFound,
					description: "Collection cursor does not match its snapshot",
				});
			if (snapshot.trustAnchor !== anchor)
				return err({
					code: FederationErrorCode.ServerError,
					description: "Invalid collection storage namespace",
				});
			let validUntil = now + (this.config.cursorTtlSeconds ?? 900);
			const entries = snapshot.entries.filter((entry) => {
				if (entry.expiresAt <= now || (entry.chainExpiresAt ?? Infinity) <= now) return false;
				if (
					request.entityType?.length &&
					!request.entityType.some((type) => entry.entity.entity_types?.includes(type))
				)
					return false;
				const marks = (request.trustMarkType ?? []).map((type) =>
					entry.verifiedMarks.filter((mark) => mark.type === type && mark.expiresAt > now),
				);
				if (marks.some((matches) => !matches.length)) return false;
				const query = request.query;
				if (query !== undefined) {
					const matcher = this.config.queryMatcher;
					if (matcher) {
						const matched = callSynchronous(
							() => matcher(query, freezeSnapshot(cloneData(entry.entity))),
							(value): value is boolean => typeof value === "boolean",
						);
						if (!matched.ok) throw new Error(`Collection query matcher failed: ${matched.error}`);
						if (!matched.value) return false;
					} else if (!collectionText(entry.entity).includes(query.toLowerCase())) return false;
				}
				validUntil = Math.min(
					validUntil,
					entry.expiresAt,
					entry.chainExpiresAt ?? Infinity,
					...marks.map((matches) => Math.max(...matches.map((mark) => mark.expiresAt))),
				);
				return true;
			});
			const start = cursor?.index ?? 0;
			if (cursor && start >= entries.length)
				return err({
					code: FederationErrorCode.PageNotFound,
					description: "Collection cursor is outside the result set",
				});
			const limit = Math.min(
				request.limit ?? this.config.maxPageSize ?? 100,
				this.config.maxPageSize ?? 100,
			);
			const page: EntityCollectionResponse["entities"] = [];

			// Reserve the complete envelope, including a cursor, before adding records.
			let bytes = utf8Encode(
				JSON.stringify({
					entities: [],
					last_updated: snapshot.lastUpdated,
					...(start < entries.length
						? {
								next: limit === 0 && cursor ? request.from : "00000000-0000-0000-0000-000000000000",
							}
						: {}),
				}),
			).byteLength;
			const maxBytes = this.config.options?.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
			if (bytes > maxBytes)
				return err({
					code: FederationErrorCode.TemporarilyUnavailable,
					description: "Collection response exceeds the response size limit",
				});
			for (const entry of entries.slice(start, start + limit)) {
				const projected = projectCollectionEntity(entry.entity, request, supportedInfoClaims);
				const size = utf8Encode(JSON.stringify(projected)).byteLength + (page.length ? 1 : 0);
				if (bytes + size > maxBytes) {
					if (!page.length)
						return err({
							code: FederationErrorCode.TemporarilyUnavailable,
							description: "A collection entry exceeds the response size limit",
						});
					break;
				}
				page.push(projected);
				bytes += size;
			}
			let next: string | undefined;
			if (start + page.length < entries.length) {
				// A zero-result continuation can reuse its validated cursor without extending its lifetime.
				if (cursor && page.length === 0) next = request.from;
				else {
					next = await randomUuid(this.config.options.engine);
					await this.store.saveCursor(
						next,
						parseStorageRecord(
							EntityCollectionCursorSchema,
							{
								snapshotId: snapshot.id,
								trustAnchor: anchor,
								context,
								index: start + page.length,
								expiresAt: Math.min(validUntil, cursor?.expiresAt ?? Infinity),
							},
							"collectionCursor",
							"save",
						),
					);
				}
			}
			return ok({ entities: page, last_updated: snapshot.lastUpdated, ...(next ? { next } : {}) });
		} catch (cause) {
			if (
				request.from !== undefined &&
				cause instanceof InvalidStorageRecordError &&
				(cause.kind === "collectionCursor" || cause.kind === "collectionSnapshot")
			)
				return err({
					code: FederationErrorCode.PageNotFound,
					description: "Invalid stored Collection continuation",
				});
			return err({
				code:
					cause instanceof EntityCollectionCursorCapacityError
						? FederationErrorCode.TemporarilyUnavailable
						: FederationErrorCode.ServerError,
				description:
					cause instanceof EntityCollectionCursorCapacityError
						? "Collection cursor capacity exhausted"
						: "Collection query failed",
				cause,
			});
		}
	}

	/** Serve anonymous or authenticated Collection requests using published snapshots. */
	async handleRequest(request: Request): Promise<Response> {
		const failure = (error: {
			code: Parameters<typeof toPublicError>[0]["code"];
			description: string;
		}) => {
			const publicError = toPublicError(error);
			return errorResponse(publicError.status, publicError.code, publicError.description);
		};
		if (request.method !== "GET" && request.method !== "POST") {
			const response = errorResponse(405, "invalid_request", "Collection requests use GET or POST");
			response.headers.set("Allow", "GET, POST");
			return response;
		}
		try {
			let form: URLSearchParams;
			const url = new URL(request.url);
			const query = url.searchParams;
			const credentialNames = endpointCredentialParameterNames(
				this.config.authentication?.extensions,
			);
			if ([...credentialNames].some((name) => query.has(name)))
				return request.method === "POST"
					? errorResponse(
							400,
							"invalid_request",
							"Authentication parameters must be in the POST body",
						)
					: errorResponse(401, "invalid_client", "Credentials require the POST form");
			const fixedNames = new Set(this.fixedQuery.keys());
			for (const name of fixedNames)
				if (
					!Object.hasOwn(COLLECTION_PARAMETERS, name) &&
					!endpointParameterValuesMatch(name, this.fixedQuery.getAll(name), query.getAll(name), [])
				)
					return errorResponse(404, "not_found", "Unknown endpoint");
			if (request.method === "POST") {
				if (
					parseContentTypeHeader(request.headers.get("content-type"))?.mediaType.toLowerCase() !==
					"application/x-www-form-urlencoded"
				)
					return errorResponse(
						400,
						"invalid_request",
						"POST requires application/x-www-form-urlencoded",
					);
				const controller = new AbortController();
				const abort = () => controller.abort();
				request.signal.addEventListener("abort", abort, { once: true });
				if (request.signal.aborted) controller.abort();
				const timer = setTimeout(
					abort,
					this.config.options?.httpTimeoutMs ?? DEFAULT_HTTP_TIMEOUT_MS,
				);
				try {
					const response = new Response(request.body, { headers: request.headers });
					form = new URLSearchParams(
						await readResponseBody(response, DEFAULT_MAX_REQUEST_BODY_BYTES, controller.signal),
					);
				} catch {
					return errorResponse(
						400,
						"invalid_request",
						"Cannot read collection request body within configured limits",
					);
				} finally {
					clearTimeout(timer);
					request.signal.removeEventListener("abort", abort);
				}
				for (const name of new Set(query.keys())) {
					if (!Object.hasOwn(COLLECTION_PARAMETERS, name)) continue;
					const values = query.getAll(name),
						configured = this.fixedQuery.getAll(name);
					if (
						!endpointParameterValuesMatch(name, configured, values, COLLECTION_UNORDERED_PARAMETERS)
					)
						return errorResponse(
							400,
							"invalid_request",
							"POST query selectors must match the configured endpoint",
						);
				}
			} else {
				if (url.search.length > DEFAULT_MAX_REQUEST_BODY_BYTES)
					return errorResponse(
						400,
						"invalid_request",
						"Collection query exceeds the request size limit",
					);
				form = new URLSearchParams(query);
			}
			for (const name of fixedNames) {
				const configured = this.fixedQuery.getAll(name);
				if (!Object.hasOwn(COLLECTION_PARAMETERS, name)) {
					if (
						form.has(name) &&
						!endpointParameterValuesMatch(name, configured, form.getAll(name), [])
					)
						return errorResponse(
							400,
							"invalid_request",
							"Body parameters conflict with endpoint query parameters",
						);
					form.delete(name);
					continue;
				}
				if (request.method === "GET" && !form.has(name)) {
					for (const value of configured) form.append(name, value);
					continue;
				}
				if (
					!endpointParameterValuesMatch(
						name,
						configured,
						form.getAll(name),
						COLLECTION_UNORDERED_PARAMETERS,
					)
				)
					return errorResponse(
						400,
						"invalid_request",
						"Request parameters conflict with endpoint fixed selectors",
					);
			}
			const authenticated = await authenticateCollectionRequest(
				form,
				request.method,
				this.config.authentication,
				this.config.options,
				request,
			);
			if (!authenticated.ok) return endpointAuthenticationErrorResponse(authenticated.error);
			for (const name of credentialNames) form.delete(name);
			const params = parseCollectionParams(form);
			if (!params.ok) return failure(params.error);
			const denied = await authorizeFederationEndpoint(
				this.config.options,
				{
					endpoint: "collection",
					receiverEntityId:
						this.config.responder?.entityId ??
						this.config.authentication?.receiverEntityId ??
						"https://collection.invalid",
					caller: authenticated.value,
				},
				form,
				request.signal,
			);
			if (denied) return denied;
			const result = await this.query(params.value);
			return result.ok ? jsonResponse(result.value) : failure(result.error);
		} catch {
			safeLogger(this.config.options?.logger)?.error("Collection request failed");
			return errorResponse(500, "server_error", "Collection request failed");
		}
	}
}
