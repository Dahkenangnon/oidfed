import {
	decodeEntityStatement,
	fetchEntityConfiguration,
	MediaType,
	validateEntityId,
} from "@oidfed/core";
import { useCallback, useState } from "react";
import { useSettings } from "@/hooks/use-settings";
import { extractFederationEntity } from "@/lib/jwt";
import { ENDPOINT_EXPECTED_TYPES, type EndpointResult, probeEndpoint } from "@/lib/probe-endpoint";

export type { EndpointResult } from "@/lib/probe-endpoint";

export interface EntitySummary {
	readonly entityId: string;
	readonly organizationName: string | null;
	readonly displayName: string | null;
	readonly description: string | null;
	readonly contacts: readonly string[];
	readonly logoUri: string | null;
	readonly entityTypes: readonly string[];
	readonly endpointAuthAlgs: readonly string[];
}

interface UseHealthCheckResult {
	readonly summary: EntitySummary | null;
	readonly results: readonly EndpointResult[];
	readonly loading: boolean;
	readonly error: string | null;
	readonly liveJwks: { keys: readonly Record<string, unknown>[] } | null;
	readonly run: (entityId: string) => void;
}

export function useHealthCheck(): UseHealthCheckResult {
	const [settings] = useSettings();
	const [summary, setSummary] = useState<EntitySummary | null>(null);
	const [results, setResults] = useState<readonly EndpointResult[]>([]);
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [liveJwks, setLiveJwks] = useState<{ keys: readonly Record<string, unknown>[] } | null>(
		null,
	);

	const run = useCallback(
		(rawEntityId: string) => {
			const controller = new AbortController();
			setLoading(true);
			setError(null);
			setSummary(null);
			setResults([]);
			setLiveJwks(null);

			const { httpTimeoutMs } = settings;

			async function execute() {
				const validated = validateEntityId(rawEntityId);
				if (!validated.ok) throw new Error(validated.error.description);

				const ecResult = await fetchEntityConfiguration(validated.value, {
					httpTimeoutMs,
					signal: controller.signal,
				});
				if (!ecResult.ok) throw new Error(ecResult.error.description);

				const decoded = decodeEntityStatement(ecResult.value);
				if (!decoded.ok) throw new Error(decoded.error.description);

				const payload = decoded.value.payload as Record<string, unknown>;
				const federationEntity = extractFederationEntity(payload);
				const metadata = payload.metadata as Record<string, Record<string, unknown>> | undefined;

				// Build summary
				const orgName = (federationEntity.organization_name as string | undefined) ?? null;
				const displayName = (federationEntity.display_name as string | undefined) ?? null;
				const description = (federationEntity.description as string | undefined) ?? null;
				const contacts = Array.isArray(federationEntity.contacts)
					? (federationEntity.contacts as string[])
					: [];
				const logoUri = (federationEntity.logo_uri as string | undefined) ?? null;
				const entityTypes = metadata ? Object.keys(metadata) : [];
				const endpointAuthAlgs = Array.isArray(
					federationEntity.endpoint_auth_signing_alg_values_supported,
				)
					? (federationEntity.endpoint_auth_signing_alg_values_supported as string[])
					: [];

				// Extract live JWKS for TA key comparison
				const jwksPayload = payload.jwks as
					| { keys: readonly Record<string, unknown>[] }
					| undefined;
				if (jwksPayload?.keys) {
					setLiveJwks(jwksPayload);
				}

				setSummary({
					entityId: rawEntityId,
					organizationName: orgName,
					displayName,
					description,
					contacts,
					logoUri,
					entityTypes,
					endpointAuthAlgs,
				});

				// Well-known endpoint (always probe)
				const wellKnownUrl = `${rawEntityId}/.well-known/openid-federation`;
				const wellKnownResult = await probeEndpoint(
					".well-known/openid-federation",
					wellKnownUrl,
					MediaType.EntityStatement,
					httpTimeoutMs,
					"get-bare",
					rawEntityId,
				);

				// Declared endpoints
				const endpointProbes = ENDPOINT_EXPECTED_TYPES.flatMap((ep) => {
					const url = federationEntity[ep.key] as string | undefined;
					if (!url) return [];
					return [
						probeEndpoint(
							ep.label,
							url,
							ep.expectedContentType,
							httpTimeoutMs,
							ep.strategy,
							rawEntityId,
						),
					];
				});

				const probeResults = await Promise.all([wellKnownResult, ...endpointProbes]);
				setResults(probeResults);
			}

			execute()
				.catch((err: unknown) => {
					setError(err instanceof Error ? err.message : "Unknown error");
				})
				.finally(() => {
					setLoading(false);
				});
		},
		[settings],
	);

	return { summary, results, loading, error, liveJwks, run };
}
