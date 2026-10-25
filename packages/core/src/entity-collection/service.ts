import {
	DEFAULT_HTTP_TIMEOUT_MS,
	DEFAULT_MAX_REQUEST_BODY_BYTES,
	DEFAULT_MAX_RESPONSE_BYTES,
	FederationErrorCode,
} from "../constants.js";
import { err, ok, type Result } from "../errors.js";
import { errorResponse, jsonResponse, parseContentTypeHeader, toPublicError } from "../http.js";
import { readResponseBody } from "../http-response.js";
import { splitInformationalClaim } from "../language-tags.js";
import { MemoryReplayStore } from "../memory-replay-store.js";
import {
	COLLECTION_INFO_CLAIMS,
	type EntityCollectionRequestParams,
	EntityCollectionRequestSchema,
	type EntityCollectionResponse,
} from "../schemas/entity-collection.js";
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
import { MemoryEntityCollectionStore } from "./store.js";
import type {
	CollectionRefreshOptions,
	CollectionRefreshResult,
	EntityCollectionConfig,
	EntityCollectionStore,
} from "./types.js";

/** Shared unsigned collection service for federation entities and independent providers. */
export class EntityCollectionService {
	readonly store: EntityCollectionStore;
	private readonly config: EntityCollectionConfig;
	private readonly refreshes = new Map<string, Promise<Result<CollectionRefreshResult>>>();
	constructor(config: EntityCollectionConfig) {
		for (const value of [
			config.maxPageSize ?? 100,
			config.cursorTtlSeconds ?? 900,
			config.maxEntities ?? 10000,
			config.options?.maxConcurrentFetches ?? 6,
			config.options?.maxTotalFetches ?? 1000,
			config.options?.maxChainDepth ?? 8,
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
		}
		const auth = config.authentication;
		if (
			config.responder &&
			auth?.receiverEntityId &&
			config.responder.entityId !== auth.receiverEntityId
		)
			throw new Error("Collection assertion audience must match the responder Entity Identifier");
		if (
			auth &&
			(!auth.methods.length ||
				auth.methods.some((method) => method !== "none" && method !== "private_key_jwt"))
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
		this.config = {
			...config,
			...(!config.responder && auth?.receiverEntityId
				? { responder: { entityId: auth.receiverEntityId, isTrustAnchor: false } }
				: {}),
			trustAnchors: new Map(config.trustAnchors),
			...(auth
				? {
						authentication: {
							...auth,
							replayStore:
								auth.replayStore ??
								new MemoryReplayStore({
									...(config.options?.clock ? { clock: config.options.clock } : {}),
								}),
						},
					}
				: {}),
		};
		this.store =
			config.store ??
			new MemoryEntityCollectionStore({
				...(config.options?.clock ? { clock: config.options.clock } : {}),
			});
	}

	async refresh(
		anchor: EntityId,
		options?: CollectionRefreshOptions,
	): Promise<Result<CollectionRefreshResult>> {
		const previous = this.refreshes.get(anchor);
		const run = (async () => {
			if (previous) await previous;
			return this.performRefresh(anchor, options);
		})();
		this.refreshes.set(anchor, run);
		try {
			return await run;
		} finally {
			if (this.refreshes.get(anchor) === run) this.refreshes.delete(anchor);
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
			await this.store.publish(built.value);
			return ok({
				snapshotId: built.value.id,
				lastUpdated: built.value.lastUpdated,
				entityCount: built.value.entries.length,
			});
		} catch (cause) {
			return err({
				code: FederationErrorCode.ServerError,
				description: "Collection publication failed",
				cause,
			});
		}
	}

	async query(
		params: EntityCollectionRequestParams = {},
	): Promise<Result<EntityCollectionResponse>> {
		const parsed = EntityCollectionRequestSchema.safeParse(params);
		if (!parsed.success)
			return err({
				code: FederationErrorCode.InvalidRequest,
				description: "Invalid collection request parameters",
			});
		const request = parsed.data;
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
			for (const claim of claims ?? [])
				if (
					!supported.includes(
						localized ? splitInformationalClaim(claim, supportedInfoClaims).base : claim,
					)
				)
					return err({
						code: FederationErrorCode.UnsupportedClaim,
						description: `Unsupported claim: ${claim}`,
					});
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
			const cursor =
				request.from === undefined ? undefined : await this.store.getCursor(request.from);
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
			const snapshot = cursor
				? await this.store.getSnapshot(cursor.snapshotId)
				: await this.store.getCurrent(anchor);
			if (!snapshot)
				return err({
					code: cursor
						? FederationErrorCode.PageNotFound
						: FederationErrorCode.TemporarilyUnavailable,
					description: "Collection snapshot is unavailable",
				});
			if (snapshot.trustAnchor !== anchor)
				return err({
					code: FederationErrorCode.ServerError,
					description: "Invalid collection storage namespace",
				});
			let validUntil = now + (this.config.cursorTtlSeconds ?? 900);
			const entries = snapshot.entries.filter((entry) => {
				if (entry.chainExpiresAt <= now) return false;
				if (
					request.entityType?.length &&
					!request.entityType.some((type) => entry.entity.entity_types?.includes(type))
				)
					return false;
				if (request.query && !collectionText(entry.entity).includes(request.query.toLowerCase()))
					return false;
				const marks = (request.trustMarkType ?? []).map((type) =>
					entry.verifiedMarks.filter((mark) => mark.type === type && mark.expiresAt > now),
				);
				if (marks.some((matches) => !matches.length)) return false;
				validUntil = Math.min(
					validUntil,
					entry.chainExpiresAt,
					...marks.map((matches) => Math.max(...matches.map((mark) => mark.expiresAt))),
				);
				return true;
			});
			const start = cursor?.index ?? 0;
			const limit = Math.min(
				request.limit ?? this.config.maxPageSize ?? 100,
				this.config.maxPageSize ?? 100,
			);
			const page: EntityCollectionResponse["entities"] = [];
			const encoder = new TextEncoder();
			// Reserve the complete envelope, including a cursor, before adding records.
			let bytes = encoder.encode(
				JSON.stringify({
					entities: [],
					last_updated: snapshot.lastUpdated,
					next: "00000000-0000-0000-0000-000000000000",
				}),
			).byteLength;
			const maxBytes = this.config.options?.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
			for (const entry of entries.slice(start, start + limit)) {
				const projected = projectCollectionEntity(entry.entity, request, supportedInfoClaims);
				const size = encoder.encode(JSON.stringify(projected)).byteLength + (page.length ? 1 : 0);
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
				next = crypto.randomUUID();
				await this.store.putCursor(next, {
					snapshotId: snapshot.id,
					trustAnchor: anchor,
					context,
					index: start + page.length,
					expiresAt: Math.min(validUntil, cursor?.expiresAt ?? Infinity),
				});
			}
			return ok({ entities: page, last_updated: snapshot.lastUpdated, ...(next ? { next } : {}) });
		} catch (cause) {
			return err({
				code: FederationErrorCode.ServerError,
				description: "Collection query failed",
				cause,
			});
		}
	}

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
			if (request.method === "POST") {
				const query = new URL(request.url).searchParams;
				if (query.has("client_assertion") || query.has("client_assertion_type"))
					return errorResponse(
						400,
						"invalid_request",
						"Client assertion parameters must be in the POST body",
					);
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
			} else {
				if (new URL(request.url).search.length > DEFAULT_MAX_REQUEST_BODY_BYTES)
					return errorResponse(
						400,
						"invalid_request",
						"Collection query exceeds the request size limit",
					);
				form = new URL(request.url).searchParams;
				if (this.config.endpoint)
					for (const [key, value] of new URL(this.config.endpoint).searchParams) {
						if (!Object.hasOwn(COLLECTION_PARAMETERS, key)) {
							const remaining = form.getAll(key);
							const at = remaining.indexOf(value);
							if (at !== -1) remaining.splice(at, 1);
							form.delete(key);
							for (const item of remaining) form.append(key, item);
						}
					}
			}
			const authenticated = await authenticateCollectionRequest(
				form,
				request.method,
				this.config.authentication,
				this.config.options,
			);
			if (!authenticated.ok) return failure(authenticated.error);
			const params = parseCollectionParams(form);
			if (!params.ok) return failure(params.error);
			const result = await this.query(params.value);
			return result.ok ? jsonResponse(result.value) : failure(result.error);
		} catch (error) {
			this.config.options?.logger?.error("Collection request failed", { error });
			return errorResponse(500, "server_error", "Collection request failed");
		}
	}
}
