import type { HistoricalKeyEntry, JWKSet } from "@oidfed/core";
import { verifyHistoricalKeysResponse } from "@oidfed/core";
import { useCallback, useRef, useState } from "react";

interface UseHistoricalKeysResult {
	readonly keys: readonly HistoricalKeyEntry[] | null;
	readonly loading: boolean;
	readonly error: string | null;
	readonly signatureValid: boolean | null;
	readonly fetch: () => void;
}

export function useHistoricalKeys(
	endpoint: string | undefined,
	issuerJwks: { keys: readonly Record<string, unknown>[] } | undefined,
): UseHistoricalKeysResult {
	const [keys, setKeys] = useState<readonly HistoricalKeyEntry[] | null>(null);
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [signatureValid, setSignatureValid] = useState<boolean | null>(null);
	const abortRef = useRef<AbortController | null>(null);

	const fetchKeys = useCallback(() => {
		if (!endpoint || !issuerJwks) return;

		abortRef.current?.abort();
		const controller = new AbortController();
		abortRef.current = controller;

		setLoading(true);
		setError(null);

		globalThis
			.fetch(endpoint, {
				signal: controller.signal,
				headers: { Accept: "application/jwk-set+jwt" },
			})
			.then(async (res) => {
				if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
				const jwt = await res.text();
				const result = await verifyHistoricalKeysResponse(jwt, {
					keys: issuerJwks.keys as JWKSet["keys"],
				});
				if (controller.signal.aborted) return;
				if (result.ok) {
					setKeys(result.value.keys);
					setSignatureValid(true);
				} else {
					setError(result.error.description);
					setSignatureValid(false);
				}
			})
			.catch((err: unknown) => {
				if (controller.signal.aborted) return;
				setError(err instanceof Error ? err.message : "Unknown error");
				setSignatureValid(false);
			})
			.finally(() => {
				if (!controller.signal.aborted) setLoading(false);
			});
	}, [endpoint, issuerJwks]);

	return { keys, loading, error, signatureValid, fetch: fetchKeys };
}
