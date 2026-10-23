import {
	type EntityId,
	FederationErrorCode,
	isValidEntityId,
	JwtTyp,
	MediaType,
	nowSeconds,
	SubordinateEventsResponseSchema,
	signEntityStatement,
} from "@oidfed/core";
import type { HandlerContext } from "./context.js";
import { errorResponse, jwtResponse, parseQueryParams, requireMethod } from "./helpers.js";

/** Apply the events error contract after both native and authenticated method checks. */
export function withSubordinateEventsMethodErrors(
	handler: (request: Request) => Promise<Response>,
): (request: Request) => Promise<Response> {
	return async (request) => {
		const response = await handler(request);
		if (response.status !== 405) return response;
		void response.body?.cancel().catch(() => {});
		const error = errorResponse(
			405,
			FederationErrorCode.InvalidRequest,
			"HTTP method is not allowed for this endpoint",
		);
		const allow = response.headers.get("Allow");
		if (allow !== null) error.headers.set("Allow", allow);
		return error;
	};
}

/** Read a consistent snapshot, then sign outside the retryable transaction. */
export async function buildSubordinateEvents(
	ctx: HandlerContext,
	subject: EntityId,
): Promise<string | undefined> {
	if (!ctx.storage.subordinateEvents)
		throw new Error("Subordinate event storage is not configured");
	const events = await ctx.storage.transaction(async (tx) => {
		if (!tx.subordinateEvents)
			throw new Error("Transaction-bound subordinateEvents is unavailable");
		const history = await tx.subordinateEvents.list(ctx.entityId, subject);
		if (history.length === 0 && !(await tx.subordinates.get(subject))) return undefined;
		return history;
	});
	if (events === undefined) return undefined;
	const payload = SubordinateEventsResponseSchema.parse({
		iss: ctx.entityId,
		sub: subject,
		iat: nowSeconds(ctx.options?.clock),
		federation_registration_events: events,
	});
	const keys = await ctx.keyProvider.getFederationKeySet();
	return signEntityStatement(payload, keys.signer, { typ: JwtTyp.EntityEventsStatement });
}

export function createSubordinateEventsHandler(
	ctx: HandlerContext,
): (request: Request) => Promise<Response> {
	return async (request) => {
		const methodError = requireMethod(request, "GET");
		if (methodError) return methodError;
		const params = parseQueryParams(request);
		const subject = params.get("sub");
		if (params.getAll("sub").length !== 1 || !subject || !isValidEntityId(subject)) {
			return errorResponse(
				400,
				FederationErrorCode.InvalidRequest,
				"Missing or invalid 'sub' parameter",
			);
		}
		try {
			const jwt = await buildSubordinateEvents(ctx, subject as EntityId);
			if (jwt === undefined)
				return errorResponse(404, FederationErrorCode.NotFound, "Entity history not found");
			return jwtResponse(jwt, MediaType.EntityEventsStatement);
		} catch (error) {
			ctx.options?.logger?.error("Failed to build subordinate events response", { error });
			return errorResponse(
				500,
				FederationErrorCode.ServerError,
				"Failed to build subordinate events response",
			);
		}
	};
}
