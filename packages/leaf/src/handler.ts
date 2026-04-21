import {
	errorResponse,
	type FederationOptions,
	jwtResponse,
	MediaType,
	requireMethod,
	WELL_KNOWN_OPENID_FEDERATION,
} from "@oidfed/core";
import type { LeafEntity } from "./entity-configuration.js";

export type FederationHandler = (request: Request) => Promise<Response>;

/** Creates an HTTP handler that serves the leaf entity's well-known federation endpoint. */
export function createLeafHandler(
	entity: LeafEntity,
	options?: FederationOptions,
): FederationHandler {
	return async (request: Request): Promise<Response> => {
		const url = new URL(request.url);
		const pathname = url.pathname;

		if (pathname === WELL_KNOWN_OPENID_FEDERATION) {
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
