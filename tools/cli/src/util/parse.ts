import { err, FederationErrorCode, federationError, ok, type Result } from "@oidfed/core";

export function parseJsonOrError(
	body: string,
	errorMessage = "Response is not valid JSON",
): Result<unknown> {
	try {
		return ok(JSON.parse(body));
	} catch {
		return err(federationError(FederationErrorCode.InvalidRequest, errorMessage));
	}
}
