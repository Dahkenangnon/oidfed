import {
	decodeEntityStatement,
	EntityConfigurationSchema,
	fetchEntityConfiguration,
	validateEntityId,
} from "@oidfed/core";
import { useCallback, useEffect, useState } from "react";
import { useSettings } from "@/hooks/use-settings";
import { addRecentEntity } from "@/lib/settings";

interface DecodedEntityConfig {
	readonly header: Record<string, unknown>;
	readonly payload: Record<string, unknown>;
	readonly validationErrors: readonly string[];
}

interface UseEntityConfigResult {
	readonly data: DecodedEntityConfig | null;
	readonly rawJwt: string | null;
	readonly loading: boolean;
	readonly error: string | null;
	readonly refetch: () => void;
}

export function useEntityConfig(entityId: string | undefined): UseEntityConfigResult {
	const [data, setData] = useState<DecodedEntityConfig | null>(null);
	const [rawJwt, setRawJwt] = useState<string | null>(null);
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [_fetchCount, setFetchCount] = useState(0);
	const [settings] = useSettings();

	const refetch = useCallback(() => setFetchCount((c) => c + 1), []);

	useEffect(() => {
		if (!entityId) {
			setData(null);
			setRawJwt(null);
			setError(null);
			return;
		}

		const controller = new AbortController();
		setLoading(true);
		setError(null);

		const validated = validateEntityId(entityId);
		if (!validated.ok) {
			setError(validated.error.description);
			setLoading(false);
			return;
		}

		fetchEntityConfiguration(validated.value, {
			httpTimeoutMs: settings.httpTimeoutMs,
			signal: controller.signal,
		})
			.then((result) => {
				if (controller.signal.aborted) return;

				if (!result.ok) {
					setError(result.error.description);
					setData(null);
					setRawJwt(null);
					return;
				}

				const jwt = result.value;
				const decoded = decodeEntityStatement(jwt);
				if (!decoded.ok) {
					setError(decoded.error.description ?? "Failed to decode JWT");
					setData(null);
					setRawJwt(null);
					return;
				}

				const { header, payload } = decoded.value;

				// Validate against EntityConfigurationSchema
				const validation = EntityConfigurationSchema.safeParse(payload);
				const validationErrors: string[] = [];
				if (!validation.success) {
					for (const issue of validation.error.issues) {
						validationErrors.push(`${issue.path.join(".")}: ${issue.message}`);
					}
				}

				setRawJwt(jwt);
				setData({
					header: header as Record<string, unknown>,
					payload: payload as unknown as Record<string, unknown>,
					validationErrors,
				});
				addRecentEntity(entityId);
			})
			.catch((err: unknown) => {
				if (controller.signal.aborted) return;
				setError(err instanceof Error ? err.message : "Unknown error");
				setData(null);
				setRawJwt(null);
			})
			.finally(() => {
				if (!controller.signal.aborted) setLoading(false);
			});

		return () => {
			controller.abort();
		};
	}, [entityId, settings.httpTimeoutMs]);

	return { data, rawJwt, loading, error, refetch };
}
