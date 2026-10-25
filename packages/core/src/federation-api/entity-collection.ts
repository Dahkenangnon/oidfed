import {
	FederationErrorCode,
	InternalErrorCode,
	JWT_BEARER_CLIENT_ASSERTION_TYPE,
	MediaType,
} from "../constants.js";
import { COLLECTION_PARAMETERS, serializeCollectionParams } from "../entity-collection/protocol.js";
import { err, ok, type Result } from "../errors.js";
import {
	type EntityCollectionRequestParams,
	EntityCollectionRequestSchema,
	type EntityCollectionResponse,
	EntityCollectionResponseSchema,
} from "../schemas/entity-collection.js";
import { performFetch, validateFetchUrl } from "../trust-chain/fetch.js";
import type { FederationOptions } from "../types.js";

export interface FetchEntityCollectionOptions extends FederationOptions {
	method?: "GET" | "POST";
	clientAssertion?: string;
}

/** Fetch informational collection data; no trust validation is implied. */
export async function fetchEntityCollection(
	endpoint: string,
	params: EntityCollectionRequestParams = {},
	options?: FetchEntityCollectionOptions,
): Promise<Result<EntityCollectionResponse>> {
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
	const method = options?.clientAssertion !== undefined ? "POST" : (options?.method ?? "GET");
	if (options?.clientAssertion !== undefined) {
		form.set("client_assertion", options.clientAssertion);
		form.set("client_assertion_type", JWT_BEARER_CLIENT_ASSERTION_TYPE);
	}
	if (method === "GET") {
		for (const name of Object.keys(COLLECTION_PARAMETERS))
			if (form.has(name)) url.searchParams.delete(name);
		for (const [name, value] of form) url.searchParams.append(name, value);
	}
	const result = await performFetch(url.toString(), {
		...options,
		method,
		...(method === "POST" ? { body: form } : {}),
		accept: MediaType.Json,
		expectedStatus: 200,
		federationErrors: true,
		contentTypePolicy: "media-type",
		redirect: "manual",
	});
	if (!result.ok) return result;
	try {
		const response = EntityCollectionResponseSchema.safeParse(JSON.parse(result.value));
		if (response.success) return ok(response.data);
	} catch {
		/* Return a protocol failure for invalid JSON. */
	}
	return err({
		code: InternalErrorCode.Network,
		description: "Invalid entity collection response",
	});
}
