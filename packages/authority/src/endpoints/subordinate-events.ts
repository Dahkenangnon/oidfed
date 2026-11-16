/** Signed subordinate history responses with request cancellation and optional expiry. */

import {
	type EntityId,
	FederationErrorCode,
	isValidEntityId,
	JwtTyp,
	MediaType,
	nowSeconds,
	SubordinateEventsResponseSchema,
	safeLogger,
	signEntityStatement,
	waitForOperation,
} from "@oidfed/core";
import type { StorageReadSnapshot } from "../storage/types.js";
import { parsePublishedSubordinateEvent } from "../utils/subordinate-event.js";
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
	requestSignal?: AbortSignal,
): Promise<string | undefined> {
	const signal = AbortSignal.any(
		[requestSignal, ctx.options?.signal].filter(
			(value): value is AbortSignal => value !== undefined,
		),
	);
	signal.throwIfAborted();
	if (!ctx.storage.subordinateEvents)
		throw new Error("Subordinate event storage is not configured");
	const read = async (tx: StorageReadSnapshot) => {
		signal.throwIfAborted();
		if (!tx.subordinateEvents)
			throw new Error("Transaction-bound subordinateEvents is unavailable");
		const history = await tx.subordinateEvents.list(ctx.entityId, subject);
		signal.throwIfAborted();
		if (history.length === 0 && !(await tx.subordinates.get(subject))) return undefined;
		return history;
	};
	const events = await waitForOperation(
		ctx.storage.readSnapshot ? ctx.storage.readSnapshot(read) : ctx.storage.transaction(read),
		[signal],
	);
	if (events === undefined) return undefined;
	const history = events.map(parsePublishedSubordinateEvent);
	const keys = await waitForOperation(ctx.keyProvider.getFederationKeySet(), [signal]);
	const iat = nowSeconds(ctx.options?.clock);
	const payload = SubordinateEventsResponseSchema.parse({
		iss: ctx.entityId,
		sub: subject,
		iat,
		...(ctx.subordinateEventsTtlSeconds !== undefined
			? { exp: iat + ctx.subordinateEventsTtlSeconds }
			: {}),
		federation_registration_events: history,
	});
	signal.throwIfAborted();
	return waitForOperation(
		signEntityStatement(payload, keys.signer, { typ: JwtTyp.EntityEventsStatement }),
		[signal],
	);
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
			const jwt = await buildSubordinateEvents(ctx, subject as EntityId, request.signal);
			if (jwt === undefined)
				return errorResponse(404, FederationErrorCode.NotFound, "Entity history not found");
			return jwtResponse(jwt, MediaType.EntityEventsStatement);
		} catch {
			safeLogger(ctx.options?.logger)?.error("Failed to build subordinate events response");
			return errorResponse(
				500,
				FederationErrorCode.ServerError,
				"Failed to build subordinate events response",
			);
		}
	};
}
