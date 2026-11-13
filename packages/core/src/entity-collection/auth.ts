import { authenticateEndpointRequest } from "../endpoint-authentication.js";
import { ok, type Result } from "../errors.js";
import type { FederationOptions } from "../types.js";
import type { CollectionAuthentication } from "./types.js";

export async function authenticateCollectionRequest(
	form: URLSearchParams,
	method: string,
	auth: CollectionAuthentication | undefined,
	options?: FederationOptions,
	request?: Request,
): Promise<Result<void>> {
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
