import {
	decodeEntityStatement,
	fetchEntityConfiguration,
	isErr,
	isOk,
	type JWKSet,
	JWKSetSchema,
	resolveTrustChains,
	type TrustAnchorSet,
	type TrustMarkDelegationPayload,
	TrustMarkDelegationPayloadSchema,
	type TrustMarkPayload,
	TrustMarkPayloadSchema,
	type ValidatedTrustMark,
	validateEntityId,
	validateTrustMark,
	verifyEntityStatement,
} from "@oidfed/core";
import { useCallback, useState } from "react";
import { useSettings } from "@/hooks/use-settings";
import { decodeJwtPart } from "@/lib/jwt";

export interface TrustMarkInspectResult {
	readonly payload: TrustMarkPayload;
	readonly validationResult: ValidatedTrustMark | null;
	readonly validationError: string | null;
	readonly delegation: TrustMarkDelegationPayload | null;
	readonly delegationVerified: boolean | null;
	readonly delegationError: string | null;
	readonly trustMarkOwner: { sub: string; fromTA: string } | null;
	readonly issuerTrusted: boolean | null;
	readonly issuerChainError: string | null;
	readonly trustedByTA: string | null;
}

interface UseTrustMarkInspectResult {
	readonly result: TrustMarkInspectResult | null;
	readonly loading: boolean;
	readonly error: string | null;
	readonly inspect: (jwt: string) => void;
}

export function useTrustMarkInspect(): UseTrustMarkInspectResult {
	const [settings] = useSettings();
	const [result, setResult] = useState<TrustMarkInspectResult | null>(null);
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState<string | null>(null);

	const inspect = useCallback(
		(jwt: string) => {
			setLoading(true);
			setError(null);
			setResult(null);

			const { httpTimeoutMs } = settings;

			async function execute() {
				// Normalize whitespace that would cause jose to reject the JWT
				const normalized = jwt.replace(/\s+/g, "");
				// Decode JWT parts
				const parts = normalized.split(".");
				if (parts.length !== 3) throw new Error("Not a valid JWT (expected 3 dot-separated parts)");

				const rawPayload = parts[1] ? decodeJwtPart(parts[1]) : null;
				if (!rawPayload) throw new Error("Failed to decode JWT payload");

				// Parse with schema
				const parsed = TrustMarkPayloadSchema.safeParse(rawPayload);
				if (!parsed.success) {
					throw new Error(
						`Invalid trust mark payload: ${parsed.error.issues[0]?.message ?? "unknown"}`,
					);
				}
				const payload = parsed.data;

				// Fetch issuer EC to get JWKS
				const validated = validateEntityId(payload.iss);
				if (!validated.ok)
					throw new Error(`Invalid issuer entity ID: ${validated.error.description}`);

				const controller = new AbortController();
				const ecResult = await fetchEntityConfiguration(validated.value, {
					httpTimeoutMs,
					signal: controller.signal,
				});
				if (!ecResult.ok)
					throw new Error(`Failed to fetch issuer EC: ${ecResult.error.description}`);

				const decodedEc = decodeEntityStatement(ecResult.value);
				if (!decodedEc.ok)
					throw new Error(`Failed to decode issuer EC: ${decodedEc.error.description}`);

				const issuerPayload = decodedEc.value.payload as Record<string, unknown>;
				const rawJwks = issuerPayload.jwks as unknown;
				const jwksParsed = JWKSetSchema.safeParse(rawJwks);
				if (!jwksParsed.success) {
					throw new Error("Issuer EC has no valid JWKS");
				}
				const issuerJwks: JWKSet = jwksParsed.data;

				// Validate trust mark — use { [type]: [] } so any issuer is accepted (signature-only check)
				const trustMarkIssuers: Record<string, string[]> = {
					[payload.trust_mark_type]: [],
				};

				const validationResult = await validateTrustMark(normalized, trustMarkIssuers, issuerJwks);

				let validatedMark: ValidatedTrustMark | null = null;
				let validationError: string | null = null;
				if (isOk(validationResult)) {
					validatedMark = validationResult.value;
				} else if (isErr(validationResult)) {
					validationError = validationResult.error.description;
				}

				// Decode delegation if present
				let delegation: TrustMarkDelegationPayload | null = null;
				if (payload.delegation) {
					const delegationParts = payload.delegation.split(".");
					const delegationRaw = delegationParts[1] ? decodeJwtPart(delegationParts[1]) : null;
					if (delegationRaw) {
						const delegationParsed = TrustMarkDelegationPayloadSchema.safeParse(delegationRaw);
						if (delegationParsed.success) {
							delegation = delegationParsed.data;
						}
					}
				}

				// T4: Verify delegation against TA's trust_mark_owners
				let delegationVerified: boolean | null = null;
				let delegationError: string | null = null;
				let trustMarkOwner: { sub: string; fromTA: string } | null = null;

				if (delegation && settings.trustAnchors.length > 0) {
					delegationVerified = false;
					for (const ta of settings.trustAnchors) {
						try {
							const taEntityId = validateEntityId(ta.entityId);
							if (!taEntityId.ok) continue;
							const taResult = await fetchEntityConfiguration(taEntityId.value, {
								httpTimeoutMs,
							});
							if (!taResult.ok) continue;
							const taDecoded = decodeEntityStatement(taResult.value);
							if (!taDecoded.ok) continue;
							const taPayload = taDecoded.value.payload as Record<string, unknown>;
							const owners = taPayload.trust_mark_owners as
								| Record<string, { sub: string; jwks: unknown }>
								| undefined;
							const owner = owners?.[payload.trust_mark_type];
							if (!owner) continue;
							if (delegation.iss !== owner.sub) continue;
							if (delegation.sub !== payload.iss) {
								delegationError = `Delegation sub '${delegation.sub}' does not match trust mark iss '${payload.iss}'`;
								continue;
							}

							// Verify delegation JWT signature against owner's JWKS
							const ownerJwksParsed = JWKSetSchema.safeParse(owner.jwks);
							if (!ownerJwksParsed.success) {
								delegationError = "Owner JWKS in TA is invalid";
								continue;
							}

							const delegationVerifyResult = await verifyEntityStatement(
								payload.delegation as string,
								ownerJwksParsed.data,
							);
							if (delegationVerifyResult.ok) {
								delegationVerified = true;
								trustMarkOwner = { sub: owner.sub, fromTA: ta.entityId };
								delegationError = null;
								break;
							}
							delegationError = `Delegation signature verification failed: ${delegationVerifyResult.error.description}`;
						} catch {
							// skip unreachable TAs
						}
					}
					if (!delegationVerified && !delegationError) {
						delegationError = "No matching trust_mark_owners entry found in configured TAs";
					}
				}

				// T5: Issuer trust chain verification
				let issuerTrusted: boolean | null = null;
				let issuerChainError: string | null = null;
				let trustedByTA: string | null = null;

				if (settings.trustAnchors.length > 0) {
					try {
						const trustAnchors = new Map() as unknown as TrustAnchorSet;
						for (const ta of settings.trustAnchors) {
							const taId = validateEntityId(ta.entityId);
							if (!taId.ok) continue;

							const taResult = await fetchEntityConfiguration(taId.value, {
								httpTimeoutMs,
							});
							if (!taResult.ok) continue;
							const taDecoded = decodeEntityStatement(taResult.value);
							if (!taDecoded.ok) continue;
							const taJwksParsed = JWKSetSchema.safeParse(
								(taDecoded.value.payload as Record<string, unknown>).jwks,
							);
							if (!taJwksParsed.success) continue;
							(trustAnchors as unknown as Map<string, JWKSet>).set(ta.entityId, taJwksParsed.data);
						}

						const chainResult = await resolveTrustChains(validated.value, trustAnchors, {
							httpTimeoutMs,
						});
						if (chainResult.chains.length > 0) {
							issuerTrusted = true;
							const firstChain = chainResult.chains[0];
							if (firstChain) {
								trustedByTA = firstChain.trustAnchorId as string;
							}
						} else {
							issuerTrusted = false;
							issuerChainError = "No valid trust chain found to any configured TA";
						}
					} catch (e) {
						issuerTrusted = false;
						issuerChainError = e instanceof Error ? e.message : "Trust chain resolution failed";
					}
				}

				setResult({
					payload,
					validationResult: validatedMark,
					validationError,
					delegation,
					delegationVerified,
					delegationError,
					trustMarkOwner,
					issuerTrusted,
					issuerChainError,
					trustedByTA,
				});
			}

			execute()
				.catch((err: unknown) => {
					setError(err instanceof Error ? err.message : "Unknown error");
				})
				.finally(() => {
					setLoading(false);
				});
		},
		[settings],
	);

	return { result, loading, error, inspect };
}
