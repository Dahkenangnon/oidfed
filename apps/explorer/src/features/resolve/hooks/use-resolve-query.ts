import {
	decodeEntityStatement,
	fetchEntityConfiguration,
	isErr,
	isOk,
	type JWKSet,
	JWKSetSchema,
	type ResolveResponsePayload,
	validateEntityId,
	verifyResolveResponse,
} from "@oidfed/core";
import { useCallback, useState } from "react";
import { useSettings } from "@/hooks/use-settings";
import { extractFederationEntity } from "@/lib/jwt";

export interface ResolveQueryParams {
	readonly resolverEntityId: string;
	readonly subject: string;
	readonly trustAnchors: readonly string[];
	readonly entityType?: string | undefined;
}

export interface ResolvePerTaResult {
	readonly trustAnchorId: string;
	readonly responsePayload: ResolveResponsePayload;
	readonly requestUrl: string;
	readonly error?: undefined;
}

export interface ResolvePerTaError {
	readonly trustAnchorId: string;
	readonly responsePayload?: undefined;
	readonly requestUrl: string;
	readonly error: string;
}

export type ResolvePerTaOutcome = ResolvePerTaResult | ResolvePerTaError;

export interface ResolveQueryResult {
	readonly results: readonly ResolvePerTaOutcome[];
	readonly resolveEndpoint: string;
}

interface UseResolveQueryResult {
	readonly result: ResolveQueryResult | null;
	readonly loading: boolean;
	readonly error: string | null;
	readonly query: (params: ResolveQueryParams) => void;
}

export function useResolveQuery(): UseResolveQueryResult {
	const [settings] = useSettings();
	const [result, setResult] = useState<ResolveQueryResult | null>(null);
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState<string | null>(null);

	const query = useCallback(
		(params: ResolveQueryParams) => {
			setLoading(true);
			setError(null);
			setResult(null);

			const { httpTimeoutMs } = settings;
			const controller = new AbortController();

			async function execute() {
				if (params.trustAnchors.length === 0) {
					throw new Error("At least one trust anchor is required");
				}

				// 1. Validate resolver entity ID
				const validatedResolver = validateEntityId(params.resolverEntityId);
				if (!validatedResolver.ok)
					throw new Error(`Invalid resolver entity ID: ${validatedResolver.error.description}`);

				// 2. Fetch resolver's EC once to find federation_resolve_endpoint and JWKS
				const ecResult = await fetchEntityConfiguration(validatedResolver.value, {
					httpTimeoutMs,
					signal: controller.signal,
				});
				if (!ecResult.ok)
					throw new Error(`Failed to fetch resolver EC: ${ecResult.error.description}`);

				const decoded = decodeEntityStatement(ecResult.value);
				if (!decoded.ok)
					throw new Error(`Failed to decode resolver EC: ${decoded.error.description}`);

				const payload = decoded.value.payload as Record<string, unknown>;
				const fedEntity = extractFederationEntity(payload);

				const resolveEndpoint = fedEntity.federation_resolve_endpoint as string | undefined;
				if (!resolveEndpoint)
					throw new Error("Resolver entity has no federation_resolve_endpoint declared");

				// Extract resolver JWKS for response verification
				const rawJwks = payload.jwks as unknown;
				const jwksParsed = JWKSetSchema.safeParse(rawJwks);
				if (!jwksParsed.success) throw new Error("Resolver EC has no valid JWKS");
				const resolverJwks: JWKSet = jwksParsed.data;

				// 3. Fire one resolve request per TA in parallel
				const outcomes = await Promise.allSettled(
					params.trustAnchors.map(async (ta): Promise<ResolvePerTaOutcome> => {
						const urlParams = new URLSearchParams({ sub: params.subject });
						urlParams.set("trust_anchor", ta);
						if (params.entityType) urlParams.set("entity_type", params.entityType);
						const requestUrl = `${resolveEndpoint}?${urlParams}`;

						const resp = await fetch(requestUrl, { signal: controller.signal });
						if (!resp.ok) {
							let errDesc = `HTTP ${resp.status}`;
							try {
								const body = (await resp.json()) as Record<string, unknown>;
								if (body.error_description) errDesc += `: ${String(body.error_description)}`;
								else if (body.error) errDesc += `: ${String(body.error)}`;
							} catch {
								// ignore parse failure
							}
							return { trustAnchorId: ta, requestUrl, error: `Resolve endpoint error: ${errDesc}` };
						}

						const jwt = await resp.text();
						const verifyResult = await verifyResolveResponse(jwt, resolverJwks);
						if (isErr(verifyResult)) {
							return {
								trustAnchorId: ta,
								requestUrl,
								error: `Response verification failed: ${verifyResult.error.description}`,
							};
						}
						if (!isOk(verifyResult)) {
							return { trustAnchorId: ta, requestUrl, error: "Response verification failed" };
						}

						return {
							trustAnchorId: ta,
							responsePayload: verifyResult.value,
							requestUrl,
						};
					}),
				);

				// Map settled results, preserving TA ordering
				const results: ResolvePerTaOutcome[] = outcomes.map((outcome, i) => {
					const ta = params.trustAnchors[i] as string;
					if (outcome.status === "fulfilled") {
						return outcome.value;
					}
					return {
						trustAnchorId: ta,
						requestUrl: `${resolveEndpoint}?sub=${encodeURIComponent(params.subject)}&trust_anchor=${encodeURIComponent(ta)}`,
						error: outcome.reason instanceof Error ? outcome.reason.message : "Unknown error",
					} satisfies ResolvePerTaError;
				});

				setResult({ results, resolveEndpoint });
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

	return { result, loading, error, query };
}
