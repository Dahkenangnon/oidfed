import { createEndpointAuthenticatedHandler } from "@oidfed/core";
import { InvalidAuthorityConfig } from "../errors.js";
import type { HandlerContext } from "./context.js";
export function createAuthenticatedHandler(
	ctx: HandlerContext,
	inner: (request: Request) => Promise<Response>,
	methods: string[] | undefined,
	options?: {
		nativeMethod?: "GET" | "POST" | undefined;
		allowedAlgorithms?: readonly string[] | undefined;
	},
): (request: Request) => Promise<Response> {
	try {
		return createEndpointAuthenticatedHandler(
			{
				receiverEntityId: ctx.entityId,
				methods: methods ?? ["none"],
				...(ctx.storage.replay ? { replayStore: ctx.storage.replay } : {}),
				getClientFederationJwks: (id) => ctx.clientKeyProvider.getClientFederationJwks(id),
				...(options?.allowedAlgorithms ? { allowedAlgorithms: options.allowedAlgorithms } : {}),
				...(ctx.endpointAuthentication ? { extensions: ctx.endpointAuthentication } : {}),
			},
			inner,
			ctx.options,
			options?.nativeMethod,
		);
	} catch (cause) {
		throw new InvalidAuthorityConfig(
			cause instanceof Error ? cause.message : "Invalid authentication configuration",
		);
	}
}
