/** Collection authentication using the shared federation endpoint verifier. */

import {
	authenticateEndpointRequest,
	type EndpointAuthenticationError,
} from "../endpoint-authentication.js";
import { ok, type Result } from "../errors.js";
import type { FederationOptions } from "../types.js";
import type { CollectionAuthentication } from "./types.js";

/**
 * Authenticate collection credentials through the shared endpoint verifier.
 * The caller remains responsible for the Collection endpoint's GET and POST request rules.
 */
export async function authenticateCollectionRequest(
	form: URLSearchParams,
	method: string,
	auth: CollectionAuthentication | undefined,
	options: FederationOptions,
	request?: Request,
): Promise<Result<void, EndpointAuthenticationError>> {
	const checked = await authenticateEndpointRequest(
		request ?? new Request("https://collection.invalid", { method }),
		form,
		{
			...auth,
			methods: auth?.methods ?? ["none"],
			receiverEntityId: auth?.receiverEntityId ?? "https://collection.invalid",
		},
		options,
	);
	return checked.ok ? ok(undefined) : checked;
}
