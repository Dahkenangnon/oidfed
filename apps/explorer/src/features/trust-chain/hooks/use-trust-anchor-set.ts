import {
	decodeEntityStatement,
	type EntityId,
	fetchEntityConfiguration,
	type TrustAnchorSet,
	validateEntityId,
} from "@oidfed/core";
import { useEffect, useState } from "react";
import { useSettings } from "@/hooks/use-settings";

interface FailedAnchor {
	readonly entityId: string;
	readonly reason: "fetch-failed" | "decode-failed" | "no-jwks" | "invalid-id";
}

interface UseTrustAnchorSetResult {
	readonly trustAnchorSet: TrustAnchorSet | null;
	readonly hasTrustAnchors: boolean;
	readonly anchorsWithoutJwks: readonly string[];
	readonly failedAnchors: readonly FailedAnchor[];
	readonly loading: boolean;
}

export function useTrustAnchorSet(): UseTrustAnchorSetResult {
	const [settings] = useSettings();
	const [trustAnchorSet, setTrustAnchorSet] = useState<TrustAnchorSet | null>(null);
	const [anchorsWithoutJwks, setAnchorsWithoutJwks] = useState<readonly string[]>([]);
	const [failedAnchors, setFailedAnchors] = useState<readonly FailedAnchor[]>([]);
	const [loading, setLoading] = useState(false);

	const { trustAnchors } = settings;
	const hasTrustAnchors = trustAnchors.length > 0;

	useEffect(() => {
		if (trustAnchors.length === 0) {
			setTrustAnchorSet(null);
			setAnchorsWithoutJwks([]);
			return;
		}

		const controller = new AbortController();
		setLoading(true);

		async function resolve() {
			const map = new Map<
				EntityId,
				Readonly<{ jwks: { keys: readonly Record<string, unknown>[] } }>
			>();
			const failed: FailedAnchor[] = [];

			for (const ta of trustAnchors) {
				if (controller.signal.aborted) return;

				// If JWKS is already provided in settings, use it directly
				if (ta.jwks && typeof ta.jwks === "object") {
					const jwks = ta.jwks as { keys: readonly Record<string, unknown>[] };
					if (Array.isArray(jwks.keys) && jwks.keys.length > 0) {
						map.set(ta.entityId as EntityId, { jwks });
						continue;
					}
				}

				// Otherwise, fetch the entity configuration to get JWKS
				const validated = validateEntityId(ta.entityId);
				if (!validated.ok) {
					failed.push({ entityId: ta.entityId, reason: "invalid-id" });
					continue;
				}

				const ecResult = await fetchEntityConfiguration(validated.value, {
					httpTimeoutMs: settings.httpTimeoutMs,
					signal: controller.signal,
				});
				if (!ecResult.ok) {
					failed.push({ entityId: ta.entityId, reason: "fetch-failed" });
					continue;
				}

				const decoded = decodeEntityStatement(ecResult.value);
				if (!decoded.ok) {
					failed.push({ entityId: ta.entityId, reason: "decode-failed" });
					continue;
				}

				const payload = decoded.value.payload as Record<string, unknown>;
				const jwks = payload.jwks as { keys: readonly Record<string, unknown>[] } | undefined;
				if (!jwks || !Array.isArray(jwks.keys) || jwks.keys.length === 0) {
					failed.push({ entityId: ta.entityId, reason: "no-jwks" });
					continue;
				}

				map.set(ta.entityId as EntityId, { jwks });
			}

			if (controller.signal.aborted) return;

			setFailedAnchors(failed);
			setAnchorsWithoutJwks(failed.map((f) => f.entityId));
			if (map.size === 0) {
				setTrustAnchorSet(null);
			} else {
				setTrustAnchorSet(map as unknown as TrustAnchorSet);
			}
			setLoading(false);
		}

		resolve().catch(() => {
			if (!controller.signal.aborted) {
				setLoading(false);
			}
		});

		return () => {
			controller.abort();
		};
	}, [trustAnchors, settings.httpTimeoutMs]);

	return { trustAnchorSet, hasTrustAnchors, anchorsWithoutJwks, failedAnchors, loading };
}
