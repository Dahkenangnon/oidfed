import { decodeEntityStatement, fetchEntityConfiguration, validateEntityId } from "@oidfed/core";
import { useEffect, useState } from "react";
import { useSettings } from "@/hooks/use-settings";
import { extractFederationEntity } from "@/lib/jwt";

export interface EnrichedEntity {
	readonly organizationName: string | null;
	readonly entityTypes: string[];
	readonly trustMarkCount: number;
}

interface UseSubordinateEnrichmentResult {
	readonly enrichment: ReadonlyMap<string, EnrichedEntity>;
	readonly loading: boolean;
}

const CONCURRENCY = 5;

export function useSubordinateEnrichment(
	entityIds: readonly string[],
): UseSubordinateEnrichmentResult {
	const [settings] = useSettings();
	const [enrichment, setEnrichment] = useState<ReadonlyMap<string, EnrichedEntity>>(new Map());
	const [loading, setLoading] = useState(false);

	useEffect(() => {
		if (entityIds.length === 0) {
			setEnrichment(new Map());
			setLoading(false);
			return;
		}

		const controller = new AbortController();
		const results = new Map<string, EnrichedEntity>();
		setLoading(true);
		setEnrichment(new Map());

		async function enrichOne(entityId: string): Promise<void> {
			if (controller.signal.aborted) return;
			try {
				const v = validateEntityId(entityId);
				if (!v.ok) return;

				const ecResult = await fetchEntityConfiguration(v.value, {
					httpTimeoutMs: settings.httpTimeoutMs,
					signal: controller.signal,
				});
				if (!ecResult.ok) return;

				const decoded = decodeEntityStatement(ecResult.value);
				if (!decoded.ok) return;

				const payload = decoded.value.payload as Record<string, unknown>;
				const fedEntity = extractFederationEntity(payload);
				const metadata = payload.metadata as Record<string, unknown> | undefined;

				const orgName = (fedEntity.organization_name as string | undefined) ?? null;
				const entityTypes = metadata ? Object.keys(metadata) : [];
				const trustMarks = fedEntity.trust_marks;
				const trustMarkCount = Array.isArray(trustMarks) ? trustMarks.length : 0;

				results.set(entityId, { organizationName: orgName, entityTypes, trustMarkCount });
			} catch {
				// skip failures silently
			}
		}

		async function execute() {
			for (let i = 0; i < entityIds.length; i += CONCURRENCY) {
				if (controller.signal.aborted) break;
				const batch = entityIds.slice(i, i + CONCURRENCY);
				await Promise.all(batch.map(enrichOne));
				if (!controller.signal.aborted) {
					setEnrichment(new Map(results));
				}
			}
		}

		execute().finally(() => {
			if (!controller.signal.aborted) setLoading(false);
		});

		return () => {
			controller.abort();
		};
	}, [entityIds, settings.httpTimeoutMs]);

	return { enrichment, loading };
}
