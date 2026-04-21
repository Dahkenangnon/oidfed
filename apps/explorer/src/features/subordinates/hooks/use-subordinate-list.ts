import { decodeEntityStatement, fetchEntityConfiguration, validateEntityId } from "@oidfed/core";
import { useCallback, useEffect, useState } from "react";
import { useSettings } from "@/hooks/use-settings";
import { extractFederationEntity } from "@/lib/jwt";

export interface SubordinateFilters {
	readonly entity_type?: string | undefined;
	readonly trust_marked?: boolean | undefined;
	readonly intermediate?: boolean | undefined;
}

interface UseSubordinateListResult {
	readonly entityIds: readonly string[];
	readonly listEndpoint: string | null;
	readonly loading: boolean;
	readonly error: string | null;
	readonly refetch: () => void;
}

export function useSubordinateList(
	authorityId: string | undefined,
	filters: SubordinateFilters,
): UseSubordinateListResult {
	const [settings] = useSettings();
	const [entityIds, setEntityIds] = useState<readonly string[]>([]);
	const [listEndpoint, setListEndpoint] = useState<string | null>(null);
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [fetchCount, setFetchCount] = useState(0);

	const refetch = useCallback(() => setFetchCount((c) => c + 1), []);

	// biome-ignore lint/correctness/useExhaustiveDependencies: fetchCount triggers refetch
	useEffect(() => {
		if (!authorityId) {
			setEntityIds([]);
			setListEndpoint(null);
			setError(null);
			return;
		}

		const validated = validateEntityId(authorityId);
		if (!validated.ok) {
			setError(validated.error.description);
			return;
		}

		const controller = new AbortController();
		setLoading(true);
		setError(null);
		setEntityIds([]);

		async function execute() {
			if (!validated.ok) return;

			const ecResult = await fetchEntityConfiguration(validated.value, {
				httpTimeoutMs: settings.httpTimeoutMs,
				signal: controller.signal,
			});
			if (!ecResult.ok) throw new Error(ecResult.error.description);

			const decoded = decodeEntityStatement(ecResult.value);
			if (!decoded.ok) throw new Error(decoded.error.description);

			const payload = decoded.value.payload as Record<string, unknown>;
			const federationEntity = extractFederationEntity(payload);
			const listUrl = federationEntity.federation_list_endpoint as string | undefined;

			if (!listUrl) {
				setListEndpoint(null);
				setEntityIds([]);
				return;
			}

			setListEndpoint(listUrl);

			// Build query params
			const params = new URLSearchParams();
			if (filters.entity_type) params.set("entity_type", filters.entity_type);
			if (filters.trust_marked !== undefined)
				params.set("trust_marked", String(filters.trust_marked));
			if (filters.intermediate !== undefined)
				params.set("intermediate", String(filters.intermediate));

			const url = params.toString() ? `${listUrl}?${params}` : listUrl;

			const response = await fetch(url, { signal: controller.signal });
			if (!response.ok) {
				throw new Error(`List endpoint returned HTTP ${response.status}`);
			}

			const data: unknown = await response.json();
			if (!Array.isArray(data)) throw new Error("List endpoint did not return a JSON array");

			const ids = data.filter((v): v is string => typeof v === "string");
			setEntityIds(ids);
		}

		execute()
			.catch((err: unknown) => {
				if (controller.signal.aborted) return;
				setError(err instanceof Error ? err.message : "Unknown error");
			})
			.finally(() => {
				if (!controller.signal.aborted) setLoading(false);
			});

		return () => {
			controller.abort();
		};
	}, [
		authorityId,
		filters.entity_type,
		filters.trust_marked,
		filters.intermediate,
		settings.httpTimeoutMs,
		fetchCount,
	]);

	return { entityIds, listEndpoint, loading, error, refetch };
}
