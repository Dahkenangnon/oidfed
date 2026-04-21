import { decodeEntityStatement, fetchEntityConfiguration, validateEntityId } from "@oidfed/core";
import { useCallback, useEffect, useRef, useState } from "react";
import { useSettings } from "@/hooks/use-settings";

interface UseTrustMarkFetchResult {
	readonly jwt: string | null;
	readonly loading: boolean;
	readonly error: string | null;
	readonly fetchTrustMark: (issuerEntityId: string, trustMarkType: string, sub: string) => void;
}

export function useTrustMarkFetch(): UseTrustMarkFetchResult {
	const [settings] = useSettings();
	const [jwt, setJwt] = useState<string | null>(null);
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const abortRef = useRef<AbortController | null>(null);

	useEffect(() => () => abortRef.current?.abort(), []);

	const fetchTrustMark = useCallback(
		(issuerEntityId: string, trustMarkType: string, sub: string) => {
			abortRef.current?.abort();
			const controller = new AbortController();
			abortRef.current = controller;

			setLoading(true);
			setError(null);
			setJwt(null);

			const { httpTimeoutMs } = settings;

			async function execute() {
				const validated = validateEntityId(issuerEntityId);
				if (!validated.ok) {
					throw new Error(`Invalid issuer entity ID: ${validated.error.description}`);
				}

				const ecResult = await fetchEntityConfiguration(validated.value, {
					httpTimeoutMs,
					signal: controller.signal,
				});
				if (!ecResult.ok) {
					throw new Error(`Failed to fetch issuer EC: ${ecResult.error.description}`);
				}

				const decodedEc = decodeEntityStatement(ecResult.value);
				if (!decodedEc.ok) {
					throw new Error(`Failed to decode issuer EC: ${decodedEc.error.description}`);
				}

				const ecPayload = decodedEc.value.payload as Record<string, unknown>;
				const fedEntity = ecPayload.metadata as Record<string, unknown> | undefined;
				const fedMeta = fedEntity?.federation_entity as Record<string, unknown> | undefined;
				const endpoint = fedMeta?.federation_trust_mark_endpoint as string | undefined;

				if (!endpoint) {
					throw new Error("Issuer does not advertise federation_trust_mark_endpoint");
				}

				const url = new URL(endpoint);
				url.searchParams.set("trust_mark_type", trustMarkType);
				url.searchParams.set("sub", sub);

				const response = await fetch(url.toString(), {
					signal: controller.signal,
				});

				if (!response.ok) {
					throw new Error(`Trust mark endpoint returned ${response.status}`);
				}

				if (controller.signal.aborted) return;

				const text = await response.text();
				if (controller.signal.aborted) return;
				setJwt(text.trim());
			}

			execute()
				.catch((err: unknown) => {
					if (controller.signal.aborted) return;
					setError(err instanceof Error ? err.message : "Unknown error");
				})
				.finally(() => {
					if (!controller.signal.aborted) setLoading(false);
				});
		},
		[settings],
	);

	return { jwt, loading, error, fetchTrustMark };
}
