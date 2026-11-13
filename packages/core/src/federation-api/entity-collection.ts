import { FederationErrorCode, InternalErrorCode, MediaType } from "../constants.js";
import { fetchFederationEndpoint } from "../endpoint-client.js";
import { serializeCollectionParams } from "../entity-collection/protocol.js";
import { err, ok, type Result } from "../errors.js";
import { safeLogger } from "./../logging.js";
import {
	createCollectionSchemas,
	type EntityCollectionRequestParams,
	EntityCollectionRequestSchema,
	type EntityCollectionResponse,
} from "../schemas/entity-collection.js";
import { validateFetchUrl } from "../trust-chain/fetch.js";
import type { FederationOptions } from "../types.js";

export interface FetchEntityCollectionOptions extends FederationOptions {
	method?: "GET" | "POST";
	clientAssertion?: string;
	/** Additional exact informational names understood by this consumer. */
	infoClaims?: readonly string[];
}

/** Fetch informational collection data; no trust validation is implied. */
export async function fetchEntityCollection(
	endpoint: string,
	params: EntityCollectionRequestParams = {},
	options?: FetchEntityCollectionOptions,
): Promise<Result<EntityCollectionResponse>> {
	safeLogger(options?.logger)?.debug("Starting fetch entity collection");

	if (
		options?.infoClaims !== undefined &&
		(!Array.isArray(options.infoClaims) ||
			!options.infoClaims.every((name) => typeof name === "string" && name.length > 0))
	)
		return err({
			code: FederationErrorCode.InvalidRequest,
			description: "Invalid informational claim declarations",
		});
	const checked = validateFetchUrl(endpoint, options);
	if (!checked.ok) return checked;
	if (checked.value.href.includes("#"))
		return err({
			code: FederationErrorCode.InvalidRequest,
			description: "Collection endpoint must not contain a fragment",
		});
	const parsed = EntityCollectionRequestSchema.safeParse(params);
	if (!parsed.success)
		return err({
			code: FederationErrorCode.InvalidRequest,
			description: "Invalid collection request parameters",
		});
	if (parsed.data.entityClaims?.length === 0 || parsed.data.infoClaims?.length === 0)
		return err({
			code: FederationErrorCode.InvalidRequest,
			description: "Empty claim selectors cannot be represented in a collection request",
		});
	const url = checked.value;
	const form = serializeCollectionParams(parsed.data);
	const result = await fetchFederationEndpoint(url.toString(), form, {
		...options,
		accept: MediaType.Json,
		expectedStatus: 200,
		federationErrors: true,
		contentTypePolicy: "media-type",
	});
	if (!result.ok) return result;
	try {
		const response = createCollectionSchemas(options?.infoClaims).response.safeParse(
			JSON.parse(result.value),
		);
		if (response.success) return ok(response.data);
	} catch {
		/* Return a protocol failure for invalid JSON. */
	}
	return err({
		code: InternalErrorCode.InvalidResponse,
		description: "Invalid entity collection response",
	});
}
