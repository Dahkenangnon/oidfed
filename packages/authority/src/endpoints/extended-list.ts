/**
 * HTTP handler for the Extended Subordinate Listing endpoint
 * (`federation_extended_list_endpoint`). Returns an ordered, paginated JSON
 * response with per-entity claim retrieval and audit timestamps, mirroring the
 * base `/federation_list` filter semantics and adding the parameters defined in
 * the Extended Subordinate Listing specification.
 */
import {
	type EntityId,
	EntityType,
	ExtendedListClaim,
	FederationErrorCode,
	nowSeconds,
} from "@oidfed/core";
import type { ListFilter, ListPageOptions, SubordinateRecord } from "../storage/types.js";
import type { HandlerContext } from "./context.js";
import { extractClaims } from "./extended-list-claims.js";
import { errorResponse, jsonResponse, parseQueryParams, requireMethod } from "./helpers.js";

/** Configuration controlling the Extended Subordinate Listing endpoint. */
export interface ExtendedListingConfig {
	/** Whether the endpoint is wired in at all. When false, handler returns 404. */
	enabled?: boolean;
	/** Hard cap applied to the per-page result size; client `limit` is clamped to this. */
	maxPageSize?: number;
	/** Default page size when the client omits `limit`. */
	defaultPageSize?: number;
	/** Whether to honour `updated_after` / `updated_before`. Defaults to true. */
	supportTimeFilters?: boolean;
	/** Whether to honour `audit_timestamps`. Defaults to true. */
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
const NON_NEG_INT = /^[0-9]+$/;

function parsePositiveInt(value: string | null): number | null {
	if (value === null) return null;
	if (!POSITIVE_INT.test(value)) return Number.NaN;
	return Number.parseInt(value, 10);
}

function parseNumericDate(value: string | null): number | null {
	if (value === null) return null;
	if (!NON_NEG_INT.test(value)) return Number.NaN;
	return Number.parseInt(value, 10);
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
	const enabled = config?.enabled ?? true;
	const maxPageSize = config?.maxPageSize ?? DEFAULT_MAX_PAGE_SIZE;
	const defaultPageSize = config?.defaultPageSize ?? DEFAULT_PAGE_SIZE;
	const supportTimeFilters = config?.supportTimeFilters ?? true;
	const supportAuditTimestamps = config?.supportAuditTimestamps ?? true;
	const defaultClaims = config?.defaultClaims ?? DEFAULT_CLAIMS;
	const maxStorePages = config?.maxStorePagesPerRequest ?? DEFAULT_MAX_STORE_PAGES;
	const storeBatchSize = config?.storeBatchSize ?? defaultPageSize;

	return async (request: Request) => {
		if (!enabled) {
			return errorResponse(404, FederationErrorCode.NotFound, "Endpoint not enabled");
		}

		const methodError = requireMethod(request, "GET");
		if (methodError) return methodError;

		const params = parseQueryParams(request);

		// ── Base-endpoint filters (entity_type, intermediate, trust_marked, trust_mark_type)
		const validEntityTypes = new Set<string>(Object.values(EntityType));
		const rawEntityTypes = params.getAll("entity_type");
		for (const et of rawEntityTypes) {
			if (!validEntityTypes.has(et)) {
				return errorResponse(400, FederationErrorCode.InvalidRequest, "Unknown entity_type value");
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
		const trustMarkType = params.get("trust_mark_type");

		if ((trustMarkedRaw !== null || trustMarkType !== null) && !ctx.storage.trustMarks) {
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
		const fromEntityId = params.get("from_entity_id");
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
				"updated_after must be a NumericDate (non-negative integer)",
			);
		}
		const updatedBeforeParam = parseNumericDate(params.get("updated_before"));
		if (updatedBeforeParam !== null && Number.isNaN(updatedBeforeParam)) {
			return errorResponse(
				400,
				FederationErrorCode.InvalidRequest,
				"updated_before must be a NumericDate (non-negative integer)",
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
				"audit_timestamps is not supported by this endpoint",
			);
		}

		// Substitute defaultClaims ONLY when the client did not send the `claims`
		// parameter at all. If `claims=` is present (even empty), the user's value
		// wins so the MUST-NOT on subordinate_statement is honoured.
		const requestedClaims = params.has("claims") ? parseClaimsParam(params) : [...defaultClaims];

		if (requestedClaims.includes(ExtendedListClaim.TrustMarks) && !ctx.storage.trustMarks) {
			return errorResponse(
				400,
				FederationErrorCode.UnsupportedParameter,
				"claims=trust_marks is not supported by this deployment",
			);
		}

		// ── from_entity_id existence validation
		if (fromEntityId !== null && fromEntityId !== "") {
			const cursorRecord = await ctx.storage.subordinates.get(fromEntityId as EntityId);
			if (!cursorRecord) {
				return errorResponse(
					400,
					FederationErrorCode.EntityIdNotFound,
					"from_entity_id does not match any subordinate",
				);
			}
		}

		// ── Build store filter + page options
		const filter: ListFilter = {};
		if (rawEntityTypes.length > 0) filter.entityTypes = rawEntityTypes as EntityType[];
		if (intermediate === true || intermediate === false) filter.intermediate = intermediate;
		const now = nowSeconds(ctx.options?.clock);
		if (trustMarked === true || trustMarked === false) filter.trustMarked = trustMarked;
		if (trustMarkType !== null) filter.trustMarkType = trustMarkType;
		if (trustMarked !== null || trustMarkType !== null) filter.validAt = now;

		const requestedLimit = limitParam ?? defaultPageSize;
		const effectiveLimit = Math.min(requestedLimit, maxPageSize);

		const baseOpts: { updatedAfter?: number; updatedBefore?: number } = {};
		if (updatedAfterParam !== null) baseOpts.updatedAfter = updatedAfterParam;
		if (updatedBeforeParam !== null) baseOpts.updatedBefore = updatedBeforeParam;

		try {
			const accumulated: SubordinateRecord[] = [];
			let storeCursor: EntityId | undefined =
				fromEntityId !== null && fromEntityId !== "" ? (fromEntityId as EntityId) : undefined;
			let nextEntityId: EntityId | undefined;
			let pagesFetched = 0;
			let storeExhausted = false;

			while (accumulated.length < effectiveLimit && pagesFetched < maxStorePages) {
				const opts: ListPageOptions = { limit: storeBatchSize, ...baseOpts };
				if (storeCursor !== undefined) opts.cursor = storeCursor;
				const page = await ctx.storage.subordinates.list(filter, opts);
				pagesFetched += 1;
				if (page.items.length === 0) {
					storeExhausted = true;
					break;
				}

				for (const record of page.items) {
					if (accumulated.length >= effectiveLimit) break;
					accumulated.push(record);
				}

				if (accumulated.length >= effectiveLimit) {
					// Page filled. The store already applied every filter, so the first
					// following record is the resume cursor.
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

			if (accumulated.length < effectiveLimit && pagesFetched >= maxStorePages && !storeExhausted) {
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
			for (const record of accumulated) {
				const entry: Record<string, unknown> = { id: record.entityId };

				if (effectiveAuditTimestamps) {
					entry.registered = record.createdAt;
					entry.updated = record.updatedAt;
				}

				if (requestedClaims.length > 0) {
					const extracted = await extractClaims(record, ctx, requestedClaims, now);
					for (const key of Object.keys(extracted)) {
						entry[key] = extracted[key];
					}
				}

				entries.push(entry);
			}

			const body: Record<string, unknown> = { immediate_subordinate_entities: entries };
			if (nextEntityId !== undefined) body.next_entity_id = nextEntityId;

			return jsonResponse(body);
		} catch (error) {
			ctx.options?.logger?.error("Failed to build extended subordinate listing", { error });
			return errorResponse(
				500,
				FederationErrorCode.ServerError,
				"Failed to build extended subordinate listing",
			);
		}
	};
}

// Re-export the claim constant so consumers can use it without a separate import.
export { ExtendedListClaim };
