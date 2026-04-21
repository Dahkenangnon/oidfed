import { type JWK, jwkThumbprint } from "@oidfed/core";
import { useEffect, useMemo, useState } from "react";
import { useSettings } from "@/hooks/use-settings";

export interface KeyComparisonEntry {
	readonly thumbprint: string;
	readonly kid: string | null;
	readonly kty: string;
	readonly alg: string | null;
	readonly status: "match" | "missing" | "extra";
}

export interface TaKeyComparisonResult {
	readonly isConfiguredTa: boolean;
	readonly hasPinnedJwks: boolean;
	readonly entries: readonly KeyComparisonEntry[];
	readonly loading: boolean;
}

export function useTaKeyComparison(
	entityId: string | null,
	liveJwks: { keys: readonly Record<string, unknown>[] } | null,
): TaKeyComparisonResult {
	const [settings] = useSettings();
	const [entries, setEntries] = useState<readonly KeyComparisonEntry[]>([]);
	const [loading, setLoading] = useState(false);

	const matchedAnchor = useMemo(() => {
		if (!entityId) return null;
		return settings.trustAnchors.find((ta) => ta.entityId === entityId) ?? null;
	}, [entityId, settings.trustAnchors]);

	const isConfiguredTa = matchedAnchor !== null;
	const pinnedJwks = matchedAnchor?.jwks as
		| { keys: readonly Record<string, unknown>[] }
		| undefined;
	const hasPinnedJwks = !!pinnedJwks?.keys?.length;

	useEffect(() => {
		if (!isConfiguredTa || !hasPinnedJwks || !liveJwks) {
			setEntries([]);
			return;
		}

		let cancelled = false;
		setLoading(true);

		async function compute() {
			const pinnedKeys = pinnedJwks?.keys ?? [];
			const liveKeys = liveJwks?.keys ?? [];

			const pinnedTps = new Map<string, Record<string, unknown>>();
			for (const key of pinnedKeys) {
				try {
					const tp = await jwkThumbprint(key as JWK);
					pinnedTps.set(tp, key);
				} catch {
					// skip invalid keys
				}
			}

			const liveTps = new Map<string, Record<string, unknown>>();
			for (const key of liveKeys) {
				try {
					const tp = await jwkThumbprint(key as JWK);
					liveTps.set(tp, key);
				} catch {
					// skip invalid keys
				}
			}

			const result: KeyComparisonEntry[] = [];

			// Matched + missing (pinned keys)
			for (const [tp, key] of pinnedTps) {
				result.push({
					thumbprint: tp,
					kid: (key.kid as string | undefined) ?? null,
					kty: String(key.kty ?? "unknown"),
					alg: (key.alg as string | undefined) ?? null,
					status: liveTps.has(tp) ? "match" : "missing",
				});
			}

			// Extra (live-only keys)
			for (const [tp, key] of liveTps) {
				if (!pinnedTps.has(tp)) {
					result.push({
						thumbprint: tp,
						kid: (key.kid as string | undefined) ?? null,
						kty: String(key.kty ?? "unknown"),
						alg: (key.alg as string | undefined) ?? null,
						status: "extra",
					});
				}
			}

			if (!cancelled) {
				setEntries(result);
				setLoading(false);
			}
		}

		compute();
		return () => {
			cancelled = true;
		};
	}, [isConfiguredTa, hasPinnedJwks, pinnedJwks, liveJwks]);

	return { isConfiguredTa, hasPinnedJwks, entries, loading };
}
