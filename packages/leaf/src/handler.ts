import {
	errorResponse,
	type FederationOptions,
	jwtResponse,
	MediaType,
	requireMethod,
	WELL_KNOWN_OPENID_FEDERATION,
} from "@oidfed/core";
import type { Leaf } from "./entity-configuration.js";

export type FederationHandler = (request: Request) => Promise<Response>;

/** Creates an HTTP handler that serves the leaf entity's well-known federation endpoint. */
export function createLeafHandler(entity: Leaf, options?: FederationOptions): FederationHandler {
	return async (request: Request): Promise<Response> => {
		const url = new URL(request.url);
		const pathname = url.pathname;
		const basePath = new URL(entity.entityId).pathname.replace(/\/$/, "");
		const wellKnownPath = `${basePath}${WELL_KNOWN_OPENID_FEDERATION}`;

		if (pathname === wellKnownPath) {
			const methodError = requireMethod(request, "GET");
			if (methodError) return methodError;

			try {
				const jwt = await entity.getEntityConfiguration();
				return jwtResponse(jwt, MediaType.EntityStatement);
			} catch (error) {
				options?.logger?.error("Failed to serve entity configuration", { error });
				return errorResponse(500, "server_error", "An internal error occurred");
			}
		}

		return errorResponse(404, "not_found", "Unknown endpoint");
	};
}
