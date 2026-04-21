import {
	type FederationError,
	resolveTrustChains,
	type TrustAnchorSet,
	type TrustChain,
	validateEntityId,
} from "@oidfed/core";
import { useCallback, useEffect, useState } from "react";
import { useSettings } from "@/hooks/use-settings";

interface UseChainResolutionResult {
	readonly chains: readonly TrustChain[];
	readonly errors: readonly FederationError[];
	readonly loading: boolean;
	readonly error: string | null;
	readonly refetch: () => void;
}

export function useChainResolution(
	entityId: string | undefined,
	trustAnchorSet: TrustAnchorSet | null,
): UseChainResolutionResult {
	const [chains, setChains] = useState<readonly TrustChain[]>([]);
	const [errors, setErrors] = useState<readonly FederationError[]>([]);
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [fetchCount, setFetchCount] = useState(0);
	const [settings] = useSettings();

	const refetch = useCallback(() => setFetchCount((c) => c + 1), []);

	// biome-ignore lint/correctness/useExhaustiveDependencies: fetchCount triggers refetch
	useEffect(() => {
		if (!entityId || !trustAnchorSet) {
			setChains([]);
			setErrors([]);
			setError(null);
			return;
		}

		const validated = validateEntityId(entityId);
		if (!validated.ok) {
			setError(validated.error.description);
			return;
		}

		const controller = new AbortController();
		setLoading(true);
		setError(null);

		resolveTrustChains(validated.value, trustAnchorSet, {
			httpTimeoutMs: settings.httpTimeoutMs,
			maxChainDepth: settings.maxChainDepth,
			signal: controller.signal,
		})
			.then((result) => {
				if (controller.signal.aborted) return;
				setChains(result.chains);
				setErrors(result.errors);

				if (result.chains.length === 0 && result.errors.length > 0) {
					setError(
						`No trust chains found. ${result.errors.length} error(s): ${result.errors[0]?.description ?? "unknown"}`,
					);
				}
			})
			.catch((err: unknown) => {
				if (controller.signal.aborted) return;
				setError(err instanceof Error ? err.message : "Unknown error during chain resolution");
				setChains([]);
				setErrors([]);
			})
			.finally(() => {
				if (!controller.signal.aborted) setLoading(false);
			});

		return () => {
			controller.abort();
		};
	}, [entityId, trustAnchorSet, settings.httpTimeoutMs, settings.maxChainDepth, fetchCount]);

	return { chains, errors, loading, error, refetch };
}
