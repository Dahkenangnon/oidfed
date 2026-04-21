import { resolveTrustChains, type TrustAnchorSet, validateEntityId } from "@oidfed/core";
import { useCallback, useState } from "react";
import type { ExpiryEntry, ScanProgress } from "@/features/expiry/hooks/use-expiry-scan";
import { getExpiryStatus } from "@/features/expiry/hooks/use-expiry-scan";
import { useSettings } from "@/hooks/use-settings";

export { getExpiryStatus };

interface UseBatchExpiryResult {
	readonly entries: readonly ExpiryEntry[];
	readonly progress: ScanProgress | null;
	readonly running: boolean;
	readonly start: (entityIds: readonly string[], trustAnchorSet: TrustAnchorSet) => void;
	readonly cancel: () => void;
}

const CONCURRENCY = 4;

export function useBatchExpiry(): UseBatchExpiryResult {
	const [settings] = useSettings();
	const [entries, setEntries] = useState<readonly ExpiryEntry[]>([]);
	const [progress, setProgress] = useState<ScanProgress | null>(null);
	const [running, setRunning] = useState(false);
	const [controller, setController] = useState<AbortController | null>(null);

	const cancel = useCallback(() => {
		controller?.abort();
	}, [controller]);

	const start = useCallback(
		(entityIds: readonly string[], trustAnchorSet: TrustAnchorSet) => {
			const ctrl = new AbortController();
			setController(ctrl);
			setRunning(true);
			setEntries([]);
			setProgress({ total: entityIds.length, done: 0 });

			const { httpTimeoutMs, maxChainDepth } = settings;
			const nowSeconds = Math.floor(Date.now() / 1000);
			const results: ExpiryEntry[] = [];
			let done = 0;

			async function processOne(entityId: string) {
				if (ctrl.signal.aborted) return;
				try {
					const v = validateEntityId(entityId);
					if (!v.ok) return;
					const chainResult = await resolveTrustChains(v.value, trustAnchorSet, {
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
					// skip individual failures
				} finally {
					done++;
					setProgress({ total: entityIds.length, done });
				}
			}

			async function execute() {
				for (let i = 0; i < entityIds.length; i += CONCURRENCY) {
					if (ctrl.signal.aborted) break;
					const batch = entityIds.slice(i, i + CONCURRENCY);
					await Promise.all(batch.map(processOne));
					if (!ctrl.signal.aborted) {
						setEntries([...results].sort((a, b) => a.expiresAt - b.expiresAt));
					}
				}
			}

			execute().finally(() => {
				if (!ctrl.signal.aborted) setRunning(false);
			});
		},
		[settings],
	);

	return { entries, progress, running, start, cancel };
}
