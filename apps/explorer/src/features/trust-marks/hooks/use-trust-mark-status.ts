import {
	decodeEntityStatement,
	fetchEntityConfiguration,
	type JWKSet,
	JWKSetSchema,
	validateEntityId,
	verifyTrustMarkStatusResponse,
} from "@oidfed/core";
import { useCallback, useEffect, useRef, useState } from "react";
import { useSettings } from "@/hooks/use-settings";

export interface TrustMarkStatusResult {
	readonly active: boolean;
	readonly rawStatus: string;
	readonly iss: string;
}

interface UseTrustMarkStatusResult {
	readonly result: TrustMarkStatusResult | null;
	readonly loading: boolean;
	readonly error: string | null;
	readonly check: (issuerEntityId: string, trustMarkJwt: string) => void;
}

export function useTrustMarkStatus(): UseTrustMarkStatusResult {
	const [settings] = useSettings();
	const [result, setResult] = useState<TrustMarkStatusResult | null>(null);
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const abortRef = useRef<AbortController | null>(null);

	useEffect(() => () => abortRef.current?.abort(), []);

	const check = useCallback(
		(issuerEntityId: string, trustMarkJwt: string) => {
			abortRef.current?.abort();
			const controller = new AbortController();
			abortRef.current = controller;

			setLoading(true);
			setError(null);
			setResult(null);

			const { httpTimeoutMs } = settings;

			async function execute() {
				// Validate issuer entity ID
				const validated = validateEntityId(issuerEntityId);
				if (!validated.ok) {
					throw new Error(`Invalid issuer entity ID: ${validated.error.description}`);
				}

				// Fetch issuer EC to get status endpoint and JWKS
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

				// Extract JWKS
				const jwksParsed = JWKSetSchema.safeParse(ecPayload.jwks);
				if (!jwksParsed.success) {
					throw new Error("Issuer EC has no valid JWKS");
				}
				const issuerJwks: JWKSet = jwksParsed.data;

				// Extract status endpoint from federation_entity metadata
				const fedEntity = ecPayload.metadata as Record<string, unknown> | undefined;
				const fedMeta = fedEntity?.federation_entity as Record<string, unknown> | undefined;
				const statusEndpoint = fedMeta?.federation_trust_mark_status_endpoint as string | undefined;

				if (!statusEndpoint) {
					throw new Error("Issuer does not advertise federation_trust_mark_status_endpoint");
				}

				const body = new URLSearchParams();
				body.set("trust_mark", trustMarkJwt);

				const response = await fetch(statusEndpoint, {
					method: "POST",
					headers: { "Content-Type": "application/x-www-form-urlencoded" },
					body: body.toString(),
					signal: controller.signal,
				});

				if (!response.ok) {
					throw new Error(`Status endpoint returned ${response.status}`);
				}

				if (controller.signal.aborted) return;

				const jwt = await response.text();
				const verified = await verifyTrustMarkStatusResponse(jwt, issuerJwks);
				if (!verified.ok) {
					throw new Error(`Failed to verify status response: ${verified.error.description}`);
				}
				const payload = verified.value;

				if (controller.signal.aborted) return;

				setResult({
					active: payload.status === "active",
					rawStatus: payload.status,
					iss: payload.iss,
				});
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

	return { result, loading, error, check };
}
