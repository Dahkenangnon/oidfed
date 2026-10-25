import {
	DEFAULT_CLOCK_SKEW_SECONDS,
	FederationErrorCode,
	JWT_BEARER_CLIENT_ASSERTION_TYPE,
} from "../constants.js";
import { err, ok, type Result } from "../errors.js";
import { verifyClientAssertion } from "../jose/client-auth.js";
import { decodeEntityStatement } from "../jose/verify.js";
import { type FederationOptions, isValidEntityId, nowSeconds } from "../types.js";
import type { CollectionAuthentication } from "./types.js";

/** Both credential fields count as supplied credentials, even when empty. */
export async function authenticateCollectionRequest(
	form: URLSearchParams,
	method: string,
	auth: CollectionAuthentication | undefined,
	options?: FederationOptions,
): Promise<Result<void>> {
	const supplied = form.has("client_assertion") || form.has("client_assertion_type");
	const methods = auth?.methods ?? ["none"];
	const invalid = (description: string) =>
		err({ code: FederationErrorCode.InvalidClient, description });
	if (!supplied)
		return methods.includes("none") ? ok(undefined) : invalid("Client authentication is required");
	if (method !== "POST" || !methods.includes("private_key_jwt"))
		return invalid("Client assertions require authenticated POST");
	if (
		form.getAll("client_assertion").length !== 1 ||
		form.getAll("client_assertion_type").length !== 1 ||
		form.get("client_assertion_type") !== JWT_BEARER_CLIENT_ASSERTION_TYPE
	)
		return invalid("Invalid client assertion parameters");
	const assertion = form.get("client_assertion") ?? "";
	const decoded = decodeEntityStatement(assertion);
	if (!decoded.ok || !isValidEntityId(decoded.value.payload.iss))
		return invalid("Invalid client assertion issuer");
	const issuer = decoded.value.payload.iss;
	if (!auth?.receiverEntityId || !auth.getClientFederationJwks)
		return invalid("Client authentication is not configured");
	const keys = await auth.getClientFederationJwks(issuer);
	if (!keys) return invalid("No trusted federation keys found for client");
	const checked = await verifyClientAssertion(assertion, keys, auth.receiverEntityId, {
		...(options?.clock ? { clock: options.clock } : {}),
		...(options?.clockSkewSeconds !== undefined
			? { clockSkewSeconds: options.clockSkewSeconds }
			: {}),
		...(auth.allowedAlgorithms ? { allowedAlgorithms: auth.allowedAlgorithms } : {}),
	});
	if (!checked.ok) return invalid("Client assertion verification failed");
	const payload = decoded.value.payload;
	const skew = options?.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;
	if (
		typeof payload.jti !== "string" ||
		!payload.jti ||
		typeof payload.exp !== "number" ||
		!Number.isFinite(payload.exp) ||
		payload.exp + skew <= nowSeconds(options?.clock)
	)
		return invalid("Client assertions require an expiration and a unique jti");
	if (
		payload.iat !== undefined &&
		(typeof payload.iat !== "number" ||
			!Number.isFinite(payload.iat) ||
			payload.iat > nowSeconds(options?.clock) + skew)
	)
		return invalid("Invalid client assertion issuance time");
	if (
		!(await auth.replayStore?.useJti({
			issuer,
			audience: auth.receiverEntityId,
			jti: payload.jti,
			expiresAt: payload.exp + skew,
		}))
	)
		return invalid("Client assertion was already used");
	form.delete("client_assertion");
	form.delete("client_assertion_type");
	return ok(undefined);
}
