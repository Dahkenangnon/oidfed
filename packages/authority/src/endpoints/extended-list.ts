/**
 * HTTP handler for the Extended Subordinate Listing endpoint
 * (`federation_extended_list_endpoint`). Returns an ordered, paginated JSON
 * response with per-entity claim retrieval and audit timestamps, mirroring the
 * base `/federation_list` filter semantics and adding the parameters defined in
 * the Extended Subordinate Listing specification.
 */
import {
	DEFAULT_MAX_RESPONSE_BYTES,
	type EntityId,
	ExtendedListQuerySchema,
	FederationErrorCode,
	isValidEntityId,
	nowSeconds,
	runAsyncOperation,
	safeLogger,
	setOwn,
	waitForOperation,
} from "@oidfed/core";
import type { ListFilter, ListPageOptions, SubordinateRecord } from "../storage/types.js";
import type { HandlerContext } from "./context.js";
import { extractClaims } from "./extended-list-claims.js";
import {
	createExtendedListFilters,
	type ExtendedListingRequestFilter,
} from "./extended-list-filters.js";
import { errorResponse, jsonResponse, parseQueryParams, requireMethod } from "./helpers.js";

/** Configuration controlling Extended Listing; numeric limits must be positive safe integers. */
export interface ExtendedListingConfig {
	/** Optional request selectors, parsed once and applied before page limits. Unknown selectors are ignored. */
	requestFilters?: Readonly<Record<string, ExtendedListingRequestFilter>>;
	/** Maximum UTF-8 JSON success-response bytes, including next; defaults to 512 KiB. */
	maxResponseBytes?: number;
	/** Whether the endpoint is wired in at all. When false, handler returns 404. */
	enabled?: boolean;
	/** Hard cap applied to the per-page result size; client `limit` is clamped to this. */
	maxPageSize?: number;
	/** Page size when `limit` is omitted; defaults to min(100, maxPageSize). */
	defaultPageSize?: number;
	/** Whether to honour `updated_after` / `updated_before`. Defaults to true. */
	supportTimeFilters?: boolean;
	/** Support explicit `audit_timestamps=true` requests. Time filters independently recommend timestamps. Defaults to true. */
	supportAuditTimestamps?: boolean;
	/**
	 * Claims substituted per-entity when the client does NOT send the `claims`
	 * parameter at all. When the client sends `claims=` (even empty), no
	 * substitution happens and the user-supplied value wins. Default:
	 * `["subordinate_statement"]`. Set to `[]` to make bare requests id-only.
	 */
	defaultClaims?: ReadonlyArray<string>;
	/**
	 * Maximum number of inner store `list()` calls allowed per HTTP request
	 * before the handler stops accumulating and returns whatever it has plus a
	 * resume cursor. Bounds worst-case work when post-filters (trust-marked,
	 * etc.) drop most records. Default: 16.
	 */
	maxStorePagesPerRequest?: number;
	/**
	 * Inner store batch size used when filling a page. Larger values reduce
	 * round-trips when post-filters are strict, smaller values bound memory.
	 * Default: `defaultPageSize`.
	 */
	storeBatchSize?: number;
}

const DEFAULT_MAX_PAGE_SIZE = 500;
const DEFAULT_PAGE_SIZE = 100;
const DEFAULT_MAX_STORE_PAGES = 16;
const DEFAULT_CLAIMS: ReadonlyArray<string> = ["subordinate_statement"];
const POSITIVE_INT = /^[1-9][0-9]*$/;

function parsePositiveInt(value: string | null): number | null {
	if (value === null) return null;
	if (!POSITIVE_INT.test(value)) return Number.NaN;
	return Number.parseInt(value, 10);
}

function parseNumericDate(value: string | null): number | null {
	if (value === null) return null;
	const parsed = ExtendedListQuerySchema.shape.updated_after.safeParse(value);
	return parsed.success ? (parsed.data ?? Number.NaN) : Number.NaN;
}

function parseBooleanQuery(value: string | null): boolean | null | undefined {
	if (value === null) return null;
	if (value === "true") return true;
	if (value === "false") return false;
	return undefined;
}

/**
 * Parse the `claims` query parameter. Accepts both repeated form
 * (`?claims=a&claims=b`) and comma-separated form (`?claims=a,b`),
 * including mixed (`?claims=a,b&claims=c`). Empty tokens are dropped.
 */
function parseClaimsParam(params: URLSearchParams): string[] {
	const raw = params.getAll("claims");
	const out: string[] = [];
	for (const value of raw) {
		for (const token of value.split(",")) {
			const trimmed = token.trim();
			if (trimmed.length > 0) out.push(trimmed);
		}
	}
	return out;
}

export function createExtendedListHandler(
	ctx: HandlerContext,
	config?: ExtendedListingConfig,
): (request: Request) => Promise<Response> {
	const requestFilters = createExtendedListFilters(config?.requestFilters, ctx);
	const enabled = config?.enabled ?? true;
	const maxPageSize = config?.maxPageSize ?? DEFAULT_MAX_PAGE_SIZE;
	const maxResponseBytes = config?.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
	const defaultPageSize = config?.defaultPageSize ?? Math.min(DEFAULT_PAGE_SIZE, maxPageSize);
	const supportTimeFilters = config?.supportTimeFilters ?? true;
	const supportAuditTimestamps = config?.supportAuditTimestamps ?? true;
	const defaultClaims = config?.defaultClaims ?? DEFAULT_CLAIMS;
	const maxStorePages = config?.maxStorePagesPerRequest ?? DEFAULT_MAX_STORE_PAGES;
	const storeBatchSize = config?.storeBatchSize ?? defaultPageSize;

	// Invalid deployment limits must fail before they can imitate an empty collection.
	for (const [name, value] of Object.entries({
		maxResponseBytes,
		maxPageSize,
		defaultPageSize,
		maxStorePagesPerRequest: maxStorePages,
		storeBatchSize,
	}))
		if (!Number.isSafeInteger(value) || value <= 0)
			throw new TypeError(`${name} must be a positive safe integer`);
	if (defaultPageSize > maxPageSize)
		throw new TypeError("defaultPageSize must not exceed maxPageSize");

	return async (request: Request) => {
		if (!enabled) {
			return errorResponse(404, FederationErrorCode.NotFound, "Endpoint not enabled");
		}

		const methodError = requireMethod(request, "GET");
		if (methodError) return methodError;

		const params = parseQueryParams(request);

		// ── Base-endpoint filters (entity_type, intermediate, trust_marked, trust_mark_type)
		// Ext-Listing §3.2 inherits the base §8.2.1 entity_type parameter, and
		// Federation §5.1 keeps its value space open (no registry): filter, never
		// reject unknown values — an unmatched identifier yields an empty page.
		const rawEntityTypes = params.getAll("entity_type");
		for (const et of rawEntityTypes) {
			if (et.length === 0) {
				return errorResponse(
					400,
					FederationErrorCode.InvalidRequest,
					"entity_type must not be empty",
				);
			}
		}

		const trustMarkedRaw = params.get("trust_marked");
		const trustMarked = parseBooleanQuery(trustMarkedRaw);
		if (trustMarkedRaw !== null && trustMarked === undefined) {
			return errorResponse(
				400,
				FederationErrorCode.InvalidRequest,
				"trust_marked must be 'true' or 'false'",
			);
		}
		const trustMarkTypes = params.getAll("trust_mark_type");

		if ((trustMarkedRaw !== null || trustMarkTypes.length > 0) && !ctx.storage.trustMarks) {
			return errorResponse(
				400,
				FederationErrorCode.UnsupportedParameter,
				"Trust mark filtering not supported",
			);
		}

		const intermediateRaw = params.get("intermediate");
		const intermediate = parseBooleanQuery(intermediateRaw);
		if (intermediateRaw !== null && intermediate === undefined) {
			return errorResponse(
				400,
				FederationErrorCode.InvalidRequest,
				"intermediate must be 'true' or 'false'",
			);
		}

		// ── Extended-endpoint parameters
		const from = params.get("from");
		const limitParam = parsePositiveInt(params.get("limit"));
		if (limitParam !== null && Number.isNaN(limitParam)) {
			return errorResponse(
				400,
				FederationErrorCode.InvalidRequest,
				"limit must be a positive integer",
			);
		}

		const updatedAfterParam = parseNumericDate(params.get("updated_after"));
		if (updatedAfterParam !== null && Number.isNaN(updatedAfterParam)) {
			return errorResponse(
				400,
				FederationErrorCode.InvalidRequest,
				"updated_after must be a finite NumericDate",
			);
		}
		const updatedBeforeParam = parseNumericDate(params.get("updated_before"));
		if (updatedBeforeParam !== null && Number.isNaN(updatedBeforeParam)) {
			return errorResponse(
				400,
				FederationErrorCode.InvalidRequest,
				"updated_before must be a finite NumericDate",
			);
		}

		if (!supportTimeFilters && (updatedAfterParam !== null || updatedBeforeParam !== null)) {
			return errorResponse(
				400,
				FederationErrorCode.UnsupportedParameter,
				"updated_after / updated_before are not supported by this endpoint",
			);
		}

		const auditTimestampsRaw = params.get("audit_timestamps");
		const auditTimestamps = parseBooleanQuery(auditTimestampsRaw);
		if (auditTimestampsRaw !== null && auditTimestamps === undefined) {
			return errorResponse(
				400,
				FederationErrorCode.InvalidRequest,
				"audit_timestamps must be 'true' or 'false'",
			);
		}
		if (!supportAuditTimestamps && auditTimestamps === true) {
			return errorResponse(
				400,
				FederationErrorCode.UnsupportedParameter,
				"Explicit audit_timestamps=true requests are not supported by this endpoint",
			);
		}

		// Substitute defaultClaims ONLY when the client did not send the `claims`
		// parameter at all. If `claims=` is present (even empty), the user's value
		// wins so the MUST-NOT on subordinate_statement is honoured.
		const requestedClaims = params.has("claims") ? parseClaimsParam(params) : [...defaultClaims];

		// ── Build store filter + page options
		const filter: ListFilter = {};
		if (rawEntityTypes.length > 0) filter.entityTypes = rawEntityTypes;
		if (intermediate === true || intermediate === false) filter.intermediate = intermediate;
		const now = nowSeconds(ctx.options?.clock);
		if (trustMarked === true) filter.trustMarked = true;
		if (trustMarkTypes.length > 0) filter.trustMarkType = trustMarkTypes;
		if (trustMarked === true || trustMarkTypes.length > 0) filter.validAt = now;

		const requestedLimit = limitParam ?? defaultPageSize;
		const effectiveLimit = Math.min(requestedLimit, maxPageSize);

		const baseOpts: { updatedAfter?: number; updatedBefore?: number } = {};
		if (updatedAfterParam !== null) baseOpts.updatedAfter = updatedAfterParam;
		if (updatedBeforeParam !== null) baseOpts.updatedBefore = updatedBeforeParam;

		try {
			const build = async (signal: AbortSignal): Promise<Response> => {
				if (signal.aborted) throw new Error("Extended listing cancelled");
				const parsedFilters = await requestFilters.prepare(params, signal);
				if (!parsedFilters.ok)
					return errorResponse(
						400,
						FederationErrorCode.InvalidRequest,
						parsedFilters.error.description,
					);
				// The wire cursor is opaque to callers; this implementation uses the store bookmark.
				if (from !== null) {
					const cursorRecord = await ctx.storage.subordinates.get(from as EntityId);
					if (!cursorRecord) {
						return errorResponse(
							404,
							FederationErrorCode.PageNotFound,
							"Unknown continuation cursor",
						);
					}
				}

				const accumulated: SubordinateRecord[] = [];
				let storeCursor: EntityId | undefined = from !== null ? (from as EntityId) : undefined;
				let nextEntityId: EntityId | undefined;
				let pagesFetched = 0;
				let storeExhausted = false;

				while (accumulated.length < effectiveLimit && pagesFetched < maxStorePages) {
					const opts: ListPageOptions = { limit: storeBatchSize, ...baseOpts };
					if (storeCursor !== undefined) opts.cursor = storeCursor;
					const page = await ctx.storage.subordinates.list(filter, opts);
					pagesFetched += 1;
					if (
						page.items.some((record) => !isValidEntityId(record.entityId)) ||
						(page.nextCursor !== undefined && !isValidEntityId(page.nextCursor))
					)
						throw new Error("Invalid subordinate identifier from storage");
					// Empty filtered pages can still have a continuation. Require progress
					// so bounded scans cannot hand the client a repeating or backward cursor.
					const lastStoreRecord = page.items[page.items.length - 1];
					if (
						page.nextCursor !== undefined &&
						((storeCursor !== undefined && page.nextCursor <= storeCursor) ||
							(lastStoreRecord !== undefined && page.nextCursor <= lastStoreRecord.entityId))
					) {
						throw new Error("Subordinate storage returned a nonadvancing cursor");
					}

					for (const record of page.items) {
						if (accumulated.length >= effectiveLimit) break;
						if (signal.aborted) throw new Error("Extended listing cancelled");
						if (await parsedFilters.value(record)) accumulated.push(record);
					}

					if (accumulated.length >= effectiveLimit) {
						// Resume at the first unexamined record; custom filters run on it
						// in the next request, without skipping any possible matches.
						const lastRecord = accumulated[accumulated.length - 1];
						if (lastRecord === undefined) break;
						const lastId = lastRecord.entityId;
						let foundInPage: EntityId | undefined;
						for (const record of page.items) {
							if (record.entityId > lastId) {
								foundInPage = record.entityId;
								break;
							}
						}
						nextEntityId = foundInPage ?? page.nextCursor;
						break;
					}

					// Not yet full: advance.
					if (page.nextCursor === undefined) {
						storeExhausted = true;
						break;
					}
					storeCursor = page.nextCursor;
				}

				if (
					accumulated.length < effectiveLimit &&
					pagesFetched >= maxStorePages &&
					!storeExhausted
				) {
					// Cap fired before fill or exhaustion — surface the store cursor for resume.
					nextEntityId = storeCursor;
				}

				// When updated_after / updated_before are used and the client did not
				// explicitly set audit_timestamps=false, include the audit timestamps
				// alongside each entry. parseBooleanQuery returns null when the param
				// is absent (and true/false when present).
				const effectiveAuditTimestamps =
					auditTimestamps === true ||
					(auditTimestamps === null && (updatedAfterParam !== null || updatedBeforeParam !== null));

				const entries: Array<Record<string, unknown>> = [];
				const encoder = new TextEncoder();
				let entryBytes = 0;
				const responseBytes = (count: number, bytes: number, next?: EntityId) =>
					encoder.encode(
						JSON.stringify({
							immediate_subordinate_entities: [],
							...(next !== undefined ? { next } : {}),
						}),
					).byteLength +
					bytes +
					Math.max(0, count - 1);
				for (const [index, record] of accumulated.entries()) {
					const entry: Record<string, unknown> = { id: record.entityId };

					if (effectiveAuditTimestamps) {
						entry.registered = record.createdAt;
						entry.updated = record.updatedAt;
					}

					if (requestedClaims.length > 0) {
						const extracted = await extractClaims(record, ctx, requestedClaims, now);
						for (const key of Object.keys(extracted)) {
							setOwn(entry, key, extracted[key]);
						}
					}

					const serialized = JSON.stringify(entry);
					const bytes = encoder.encode(serialized).byteLength;
					const following = accumulated[index + 1]?.entityId ?? nextEntityId;
					// Draft 03 §3.1.2: account for selected claims and the actual next cursor.
					// The preceding accepted entry already reserved space for this record's cursor.
					if (responseBytes(entries.length + 1, entryBytes + bytes, following) > maxResponseBytes) {
						if (!entries.length)
							throw new Error("A subordinate entry exceeds the response size limit");
						nextEntityId = record.entityId;
						break;
					}
					// Retain the measured JSON so custom store objects cannot change between
					// measurement and response serialization while later entries are awaited.
					entries.push(JSON.parse(serialized) as Record<string, unknown>);
					entryBytes += bytes;
				}
				if (responseBytes(entries.length, entryBytes, nextEntityId) > maxResponseBytes)
					throw new Error("Extended listing envelope exceeds the response size limit");

				const body: Record<string, unknown> = { immediate_subordinate_entities: entries };
				if (nextEntityId !== undefined) body.next = nextEntityId;

				if (signal.aborted) throw new Error("Extended listing cancelled");
				return jsonResponse(body);
			};
			// One deadline covers parsing and the entire custom-filter scan, not one timeout per record.
			const signal = ctx.options?.signal
				? AbortSignal.any([request.signal, ctx.options.signal])
				: request.signal;
			return await waitForOperation(
				requestFilters.present(params)
					? runAsyncOperation(build, { ...ctx.options, signal })
					: build(signal),
				[signal],
			);
		} catch {
			safeLogger(ctx.options?.logger)?.error("Failed to build extended subordinate listing");
			return errorResponse(
				500,
				FederationErrorCode.ServerError,
				"Failed to build extended subordinate listing",
			);
		}
	};
}
