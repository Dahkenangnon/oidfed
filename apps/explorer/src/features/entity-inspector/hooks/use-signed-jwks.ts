import type { JWKSet } from "@oidfed/core";
import { verifyHistoricalKeysResponse } from "@oidfed/core";
import { useCallback, useRef, useState } from "react";

interface UseSignedJwksResult {
	readonly keys: readonly Record<string, unknown>[] | null;
	readonly loading: boolean;
	readonly error: string | null;
	readonly signatureValid: boolean | null;
	readonly fetch: () => void;
}

export function useSignedJwks(
	uri: string | undefined,
	issuerJwks: { keys: readonly Record<string, unknown>[] } | undefined,
): UseSignedJwksResult {
	const [keys, setKeys] = useState<readonly Record<string, unknown>[] | null>(null);
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [signatureValid, setSignatureValid] = useState<boolean | null>(null);
	const abortRef = useRef<AbortController | null>(null);

	const fetchKeys = useCallback(() => {
		if (!uri || !issuerJwks) return;

		abortRef.current?.abort();
		const controller = new AbortController();
		abortRef.current = controller;

		setLoading(true);
		setError(null);

		globalThis
			.fetch(uri, {
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
					setKeys(result.value.keys as unknown as Record<string, unknown>[]);
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
	}, [uri, issuerJwks]);

	return { keys, loading, error, signatureValid, fetch: fetchKeys };
}
