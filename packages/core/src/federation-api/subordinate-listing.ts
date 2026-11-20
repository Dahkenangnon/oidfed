import { type EntityTypeIdentifier, InternalErrorCode, MediaType } from "../constants.js";
import { fetchFederationEndpoint } from "../endpoint-client.js";
import { LIST_UNORDERED_PARAMETERS } from "../endpoint-parameters.js";
import { err, type FederationError, ok, type Result } from "../errors.js";
import { safeLogger } from "../logging.js";
import { EntityIdSchema } from "../schemas/entity-id.js";
import type { EntityId, FederationOptions } from "../types.js";

/** Optional filters accepted by the subordinate listing endpoint. */
export interface ListSubordinatesFilter {
	/** Accept extension Entity Type Identifiers as permitted by Federation §5.1. */
	entityType?: EntityTypeIdentifier | EntityTypeIdentifier[];
	trustMarked?: boolean;
	trustMarkType?: string;
	intermediate?: boolean;
}

/**
 * Fetch an authority's subordinate listing and return its Entity Identifiers.
 * Configure the endpoint and authentication together from trusted configuration or validated metadata.
 * This standalone client uses authentication.audience without an independent responder identity;
 * getEndpointAuthentication receives no responder. Authenticated requests use POST and never retry anonymously.
 * Collection traversal supplies its known authority identity for an additional audience check.
 */
export async function fetchListSubordinates(
	listEndpoint: string,
	filter: ListSubordinatesFilter | undefined,
	options: FederationOptions,
): Promise<Result<EntityId[], FederationError>> {
	return requestListSubordinates(listEndpoint, filter, options);
}

/** Internal traversal entry point with an independently known endpoint owner. */
export function fetchListSubordinatesForIssuer(
	listEndpoint: string,
	issuer: EntityId,
	options: FederationOptions,
): Promise<Result<EntityId[], FederationError>> {
	return requestListSubordinates(listEndpoint, undefined, options, issuer);
}

async function requestListSubordinates(
	listEndpoint: string,
	filter: ListSubordinatesFilter | undefined,
	options: FederationOptions,
	issuer?: EntityId,
): Promise<Result<EntityId[], FederationError>> {
	safeLogger(options?.logger)?.debug("Starting fetch list subordinates");

	let url: URL;
	try {
		url = new URL(listEndpoint);
	} catch (cause) {
		return err({
			code: InternalErrorCode.Network,
			description: `Invalid list endpoint URL: ${listEndpoint}`,
			cause,
		});
	}

	const selectors = new URLSearchParams();
	if (filter?.entityType !== undefined) {
		const types = Array.isArray(filter.entityType) ? filter.entityType : [filter.entityType];
		for (const t of types) selectors.append("entity_type", t);
	}
	if (filter?.trustMarked !== undefined) {
		selectors.set("trust_marked", filter.trustMarked ? "true" : "false");
	}
	if (filter?.trustMarkType !== undefined) {
		selectors.set("trust_mark_type", filter.trustMarkType);
	}
	if (filter?.intermediate !== undefined) {
		selectors.set("intermediate", filter.intermediate ? "true" : "false");
	}

	const result = await fetchFederationEndpoint(
		url.toString(),
		selectors,
		{
			...(options ?? {}),
			method: "GET",
			expectedStatus: 200,
			federationErrors: true,
			accept: MediaType.Json,
		},
		issuer,
		LIST_UNORDERED_PARAMETERS,
	);
	if (!result.ok) return result;

	let parsed: unknown;
	try {
		parsed = JSON.parse(result.value);
	} catch (cause) {
		return err({
			code: InternalErrorCode.Network,
			description: `List endpoint returned non-JSON body: ${listEndpoint}`,
			cause,
		});
	}
	if (!Array.isArray(parsed) || !parsed.every((v) => EntityIdSchema.safeParse(v).success)) {
		return err({
			code: InternalErrorCode.Network,
			description: `List endpoint did not return a JSON array of Entity Identifiers: ${listEndpoint}`,
		});
	}
	return ok(parsed as EntityId[]);
}
