import {
	type EntityId,
	entityId,
	err,
	FederationErrorCode,
	federationError,
	ok,
	type Result,
} from "@oidfed/core";

export function parseEntityIdOrError(raw: string): Result<EntityId> {
	try {
		return ok(entityId(raw));
	} catch (e) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				e instanceof Error ? e.message : "Invalid entity ID",
			),
		);
	}
}
