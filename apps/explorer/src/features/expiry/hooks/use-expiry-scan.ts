import {
	decodeEntityStatement,
	fetchEntityConfiguration,
	resolveTrustChains,
	type TrustAnchorSet,
	validateEntityId,
} from "@oidfed/core";
import { useCallback, useState } from "react";
import { useSettings } from "@/hooks/use-settings";
import { extractFederationEntity } from "@/lib/jwt";

export interface ExpiryEntry {
	readonly entityId: string;
	readonly trustAnchorId: string;
	readonly expiresAt: number; // unix seconds
	readonly daysRemaining: number;
	readonly expired: boolean;
}

export type ExpiryStatus = "expired" | "critical" | "warning" | "soon" | "ok";

export function getExpiryStatus(
	daysRemaining: number,
	thresholds: readonly number[],
): ExpiryStatus {
	const sorted = [...thresholds].sort((a, b) => a - b);
	const [t1 = 7, t2 = 30] = sorted;
	if (daysRemaining <= 0) return "expired";
	if (daysRemaining <= t1) return "critical";
	if (daysRemaining <= t2) return "warning";
	if (daysRemaining <= (sorted[2] ?? 90)) return "soon";
	return "ok";
}

export interface ScanProgress {
	readonly total: number;
	readonly done: number;
}

interface UseExpiryScanResult {
	readonly entries: readonly ExpiryEntry[];
	readonly progress: ScanProgress | null;
	readonly loading: boolean;
	readonly error: string | null;
	readonly scan: (authorityId: string, taSet: TrustAnchorSet) => void;
	readonly abort: () => void;
}

export function useExpiryScan(): UseExpiryScanResult {
	const [settings] = useSettings();
	const [entries, setEntries] = useState<readonly ExpiryEntry[]>([]);
	const [progress, setProgress] = useState<ScanProgress | null>(null);
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [controller, setController] = useState<AbortController | null>(null);

	const abort = useCallback(() => {
		controller?.abort();
	}, [controller]);

	const scan = useCallback(
		(authorityId: string, taSet: TrustAnchorSet) => {
			const ctrl = new AbortController();
			setController(ctrl);
			setLoading(true);
			setError(null);
			setEntries([]);
			setProgress(null);

			const { httpTimeoutMs, maxChainDepth } = settings;
			const nowSeconds = Math.floor(Date.now() / 1000);

			async function execute() {
				// 1. Fetch authority EC to get list endpoint
				const validated = validateEntityId(authorityId);
				if (!validated.ok) throw new Error(validated.error.description);

				const ecResult = await fetchEntityConfiguration(validated.value, {
					httpTimeoutMs,
					signal: ctrl.signal,
				});
				if (!ecResult.ok) throw new Error(ecResult.error.description);

				const decoded = decodeEntityStatement(ecResult.value);
				if (!decoded.ok) throw new Error(decoded.error.description);

				const payload = decoded.value.payload as Record<string, unknown>;
				const fedEntity = extractFederationEntity(payload);
				const listUrl = fedEntity.federation_list_endpoint as string | undefined;

				if (!listUrl) throw new Error("Authority has no federation_list_endpoint");

				// 2. Fetch subordinate list
				const listResp = await fetch(listUrl, { signal: ctrl.signal });
				if (!listResp.ok) throw new Error(`List endpoint returned HTTP ${listResp.status}`);
				const listData: unknown = await listResp.json();
				if (!Array.isArray(listData)) throw new Error("List endpoint did not return JSON array");
				const entityIds = listData.filter((v): v is string => typeof v === "string");

				setProgress({ total: entityIds.length, done: 0 });

				// 3. Resolve chains for each entity — concurrency-limited
				const CONCURRENCY = 4;
				const results: ExpiryEntry[] = [];
				let done = 0;

				async function processOne(entityId: string) {
					if (ctrl.signal.aborted) return;
					try {
						const v = validateEntityId(entityId);
						if (!v.ok) return;
						const chainResult = await resolveTrustChains(v.value, taSet, {
							httpTimeoutMs,
							maxChainDepth,
							signal: ctrl.signal,
						});
						for (const chain of chainResult.chains) {
							const daysRemaining = Math.floor((chain.expiresAt - nowSeconds) / 86400);
							results.push({
								entityId,
								trustAnchorId: chain.trustAnchorId,
								expiresAt: chain.expiresAt,
								daysRemaining,
								expired: chain.expiresAt <= nowSeconds,
							});
						}
					} catch {
						// skip individual failures — don't abort the whole scan
					} finally {
						done++;
						setProgress({ total: entityIds.length, done });
					}
				}

				// Process in batches
				for (let i = 0; i < entityIds.length; i += CONCURRENCY) {
					if (ctrl.signal.aborted) break;
					const batch = entityIds.slice(i, i + CONCURRENCY);
					await Promise.all(batch.map(processOne));
					// Update results incrementally
					setEntries([...results].sort((a, b) => a.expiresAt - b.expiresAt));
				}
			}

			execute()
				.catch((err: unknown) => {
					if (ctrl.signal.aborted) return;
					setError(err instanceof Error ? err.message : "Unknown error");
				})
				.finally(() => {
					if (!ctrl.signal.aborted) setLoading(false);
				});
		},
		[settings],
	);

	return { entries, progress, loading, error, scan, abort };
}
