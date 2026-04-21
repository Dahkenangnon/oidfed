import {
	decodeEntityStatement,
	fetchEntityConfiguration,
	MediaType,
	validateEntityId,
} from "@oidfed/core";
import { useCallback, useState } from "react";
import { useSettings } from "@/hooks/use-settings";
import { extractFederationEntity } from "@/lib/jwt";
import { ENDPOINT_EXPECTED_TYPES, probeEndpoint } from "@/lib/probe-endpoint";

export interface BatchHealthResult {
	readonly ok: number;
	readonly fail: number;
	readonly total: number;
}

interface UseBatchHealthResult {
	readonly results: ReadonlyMap<string, BatchHealthResult>;
	readonly progress: { readonly done: number; readonly total: number };
	readonly running: boolean;
	readonly start: (entityIds: readonly string[]) => void;
	readonly cancel: () => void;
}

const CONCURRENCY = 4;

export function useBatchHealth(): UseBatchHealthResult {
	const [settings] = useSettings();
	const [results, setResults] = useState<ReadonlyMap<string, BatchHealthResult>>(new Map());
	const [progress, setProgress] = useState({ done: 0, total: 0 });
	const [running, setRunning] = useState(false);
	const [controller, setController] = useState<AbortController | null>(null);

	const cancel = useCallback(() => {
		controller?.abort();
	}, [controller]);

	const start = useCallback(
		(entityIds: readonly string[]) => {
			const ctrl = new AbortController();
			setController(ctrl);
			setRunning(true);
			setResults(new Map());
			setProgress({ done: 0, total: entityIds.length });

			const { httpTimeoutMs } = settings;
			const map = new Map<string, BatchHealthResult>();
			let done = 0;

			async function checkOne(entityId: string) {
				if (ctrl.signal.aborted) return;
				try {
					const v = validateEntityId(entityId);
					if (!v.ok) {
						map.set(entityId, { ok: 0, fail: 1, total: 1 });
						return;
					}

					const ecResult = await fetchEntityConfiguration(v.value, {
						httpTimeoutMs,
						signal: ctrl.signal,
					});
					if (!ecResult.ok) {
						map.set(entityId, { ok: 0, fail: 1, total: 1 });
						return;
					}

					const decoded = decodeEntityStatement(ecResult.value);
					if (!decoded.ok) {
						map.set(entityId, { ok: 0, fail: 1, total: 1 });
						return;
					}

					const payload = decoded.value.payload as Record<string, unknown>;
					const fedEntity = extractFederationEntity(payload);

					// Probe well-known + declared endpoints
					const wellKnownUrl = `${entityId}/.well-known/openid-federation`;
					const probes = [
						probeEndpoint(
							".well-known",
							wellKnownUrl,
							MediaType.EntityStatement,
							httpTimeoutMs,
							"get-bare",
							entityId,
						),
					];

					for (const ep of ENDPOINT_EXPECTED_TYPES) {
						const url = fedEntity[ep.key] as string | undefined;
						if (url) {
							probes.push(
								probeEndpoint(
									ep.label,
									url,
									ep.expectedContentType,
									httpTimeoutMs,
									ep.strategy,
									entityId,
								),
							);
						}
					}

					const probeResults = await Promise.all(probes);
					const okCount = probeResults.filter((r) => r.ok).length;
					map.set(entityId, {
						ok: okCount,
						fail: probeResults.length - okCount,
						total: probeResults.length,
					});
				} catch {
					map.set(entityId, { ok: 0, fail: 1, total: 1 });
				} finally {
					done++;
					setProgress({ done, total: entityIds.length });
				}
			}

			async function execute() {
				for (let i = 0; i < entityIds.length; i += CONCURRENCY) {
					if (ctrl.signal.aborted) break;
					const batch = entityIds.slice(i, i + CONCURRENCY);
					await Promise.all(batch.map(checkOne));
					if (!ctrl.signal.aborted) {
						setResults(new Map(map));
					}
				}
			}

			execute().finally(() => {
				if (!ctrl.signal.aborted) setRunning(false);
			});
		},
		[settings],
	);

	return { results, progress, running, start, cancel };
}
