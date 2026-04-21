import { decodeEntityStatement, fetchEntityConfiguration, validateEntityId } from "@oidfed/core";
import { useCallback, useEffect, useRef, useState } from "react";
import { useSettings } from "@/hooks/use-settings";

interface UseTrustMarkListResult {
	readonly items: string[] | null;
	readonly loading: boolean;
	readonly error: string | null;
	readonly fetchList: (
		issuerEntityId: string,
		trustMarkType: string,
		sub?: string | undefined,
	) => void;
}

export function useTrustMarkList(): UseTrustMarkListResult {
	const [settings] = useSettings();
	const [items, setItems] = useState<string[] | null>(null);
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const abortRef = useRef<AbortController | null>(null);

	useEffect(() => () => abortRef.current?.abort(), []);

	const fetchList = useCallback(
		(issuerEntityId: string, trustMarkType: string, sub?: string | undefined) => {
			abortRef.current?.abort();
			const controller = new AbortController();
			abortRef.current = controller;

			setLoading(true);
			setError(null);
			setItems(null);

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
				const endpoint = fedMeta?.federation_trust_mark_list_endpoint as string | undefined;

				if (!endpoint) {
					throw new Error("Issuer does not advertise federation_trust_mark_list_endpoint");
				}

				const url = new URL(endpoint);
				url.searchParams.set("trust_mark_type", trustMarkType);
				if (sub) url.searchParams.set("sub", sub);

				const response = await fetch(url.toString(), {
					signal: controller.signal,
				});

				if (!response.ok) {
					throw new Error(`Trust mark list endpoint returned ${response.status}`);
				}

				if (controller.signal.aborted) return;

				const json = await response.json();
				if (!Array.isArray(json)) {
					throw new Error("Expected JSON array response");
				}
				if (!json.every((item: unknown) => typeof item === "string")) {
					throw new Error("Expected array of entity identifier strings");
				}

				if (controller.signal.aborted) return;
				setItems(json as string[]);
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

	return { items, loading, error, fetchList };
}
