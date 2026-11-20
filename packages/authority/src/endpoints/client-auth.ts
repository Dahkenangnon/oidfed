/** Authority adapter for shared federation endpoint authentication. */

import { createEndpointAuthenticatedHandler } from "@oidfed/core";
import { InvalidAuthorityConfig } from "../errors.js";
import type { HandlerContext } from "./context.js";

/**
 * Adapt authority configuration to the shared endpoint authentication wrapper.
 * Invalid authentication configuration is reported as InvalidAuthorityConfig.
 */
export function createAuthenticatedHandler(
	ctx: HandlerContext,
	inner: (request: Request) => Promise<Response>,
	methods: string[] | undefined,
	options?: {
		nativeMethod?: "GET" | "POST" | undefined;
		unorderedParameters?: readonly string[] | undefined;
		allowedAlgorithms?: readonly string[] | undefined;
	},
): (request: Request) => Promise<Response> {
	try {
		return createEndpointAuthenticatedHandler(
			{
				receiverEntityId: ctx.entityId,
				methods: methods ?? ["none"],
				getClientFederationJwks: (id) => ctx.clientKeyProvider.getClientFederationJwks(id),
				...(options?.allowedAlgorithms ? { allowedAlgorithms: options.allowedAlgorithms } : {}),
				...(ctx.endpointAuthentication ? { extensions: ctx.endpointAuthentication } : {}),
			},
			inner,
			{ ...ctx.options, storage: ctx.storage },
			options?.nativeMethod,
			options?.unorderedParameters,
		);
	} catch (cause) {
		throw new InvalidAuthorityConfig(
			cause instanceof Error ? cause.message : "Invalid authentication configuration",
		);
	}
}
