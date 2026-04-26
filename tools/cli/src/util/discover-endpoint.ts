import {
	decodeEntityStatement,
	type EntityId,
	err,
	FederationErrorCode,
	federationError,
	fetchEntityConfiguration,
	type HttpClient,
	ok,
	type Result,
} from "@oidfed/core";

/**
 * Fetch an entity's configuration and extract a federation endpoint URL
 * advertised under `metadata.federation_entity[metadataKey]`.
 *
 * The federation endpoints (fetch, list, resolve, trust-mark, trust-mark-list,
 * trust-mark-status, historical-keys) are advertised by URL in the EC metadata
 * and may live at any path; consumers MUST use the published URL rather than
 * assuming a conventional location.
 */
export async function discoverEndpoint(
	entityId: EntityId,
	metadataKey: string,
	httpClient: HttpClient,
): Promise<Result<string>> {
	const ecResult = await fetchEntityConfiguration(entityId, { httpClient });
	if (!ecResult.ok) return ecResult;

	const decoded = decodeEntityStatement(ecResult.value);
	if (!decoded.ok) return decoded;

	const payload = decoded.value.payload as Record<string, unknown>;
	const metadata = payload.metadata as Record<string, Record<string, unknown>> | undefined;
	const fedEntity = metadata?.federation_entity;
	const endpoint = fedEntity?.[metadataKey] as string | undefined;

	if (!endpoint || typeof endpoint !== "string") {
		return err(
			federationError(
				FederationErrorCode.NotFound,
				`Entity ${entityId} does not advertise ${metadataKey} in federation_entity metadata`,
			),
		);
	}

	return ok(endpoint);
}
