import {
	decodeEntityStatement,
	fetchEntityConfiguration,
	type JWKSet,
	type ValidatedTrustMark,
	validateEntityId,
	validateTrustMark,
} from "@oidfed/core";
import { useCallback, useState } from "react";
import { useSettings } from "@/hooks/use-settings";

type ValidationStatus = "idle" | "verifying" | "valid" | "invalid" | "expired" | "error";

interface UseTrustMarkValidationResult {
	readonly status: ValidationStatus;
	readonly details: ValidatedTrustMark | null;
	readonly error: string | null;
	readonly verify: () => void;
}

function decodeTrustMarkPayloadUnsafe(jwt: string): Record<string, unknown> | null {
	try {
		const parts = jwt.split(".");
		if (parts.length !== 3 || !parts[1]) return null;
		return JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/"))) as Record<
			string,
			unknown
		>;
	} catch {
		return null;
	}
}

export function useTrustMarkValidation(trustMarkJwt: string): UseTrustMarkValidationResult {
	const [status, setStatus] = useState<ValidationStatus>("idle");
	const [details, setDetails] = useState<ValidatedTrustMark | null>(null);
	const [error, setError] = useState<string | null>(null);
	const [settings] = useSettings();

	const verify = useCallback(() => {
		setStatus("verifying");
		setError(null);
		setDetails(null);

		const run = async () => {
			// 1. Decode to get issuer
			const payload = decodeTrustMarkPayloadUnsafe(trustMarkJwt);
			if (!payload?.iss || typeof payload.iss !== "string") {
				setStatus("error");
				setError("Cannot decode trust mark: missing iss claim");
				return;
			}

			// 2. Fetch issuer's EC to get JWKS
			const issEntityId = validateEntityId(payload.iss);
			if (!issEntityId.ok) {
				setStatus("error");
				setError(`Invalid issuer entity ID: ${issEntityId.error.description}`);
				return;
			}
			const ecResult = await fetchEntityConfiguration(issEntityId.value, {
				httpTimeoutMs: settings.httpTimeoutMs,
			});
			if (!ecResult.ok) {
				setStatus("error");
				setError(`Failed to fetch issuer EC: ${ecResult.error.description}`);
				return;
			}

			const decoded = decodeEntityStatement(ecResult.value);
			if (!decoded.ok) {
				setStatus("error");
				setError(`Failed to decode issuer EC: ${decoded.error.description}`);
				return;
			}

			const issuerJwks = (decoded.value.payload as Record<string, unknown>).jwks as
				| { keys: Record<string, unknown>[] }
				| undefined;
			if (!issuerJwks?.keys?.length) {
				setStatus("error");
				setError("Issuer EC has no JWKS");
				return;
			}

			// 3. Build trust mark issuers map from configured TAs
			let trustMarkIssuers: Record<string, string[]> = {};
			for (const ta of settings.trustAnchors) {
				try {
					const taEntityId = validateEntityId(ta.entityId);
					if (!taEntityId.ok) continue;
					const taResult = await fetchEntityConfiguration(taEntityId.value, {
						httpTimeoutMs: settings.httpTimeoutMs,
					});
					if (!taResult.ok) continue;
					const taDecoded = decodeEntityStatement(taResult.value);
					if (!taDecoded.ok) continue;
					const taPayload = taDecoded.value.payload as Record<string, unknown>;
					if (taPayload.trust_mark_issuers && typeof taPayload.trust_mark_issuers === "object") {
						trustMarkIssuers = {
							...trustMarkIssuers,
							...(taPayload.trust_mark_issuers as Record<string, string[]>),
						};
					}
				} catch {
					// skip unreachable TAs
				}
			}

			// If no TAs configured, allow any issuer for the trust mark type
			const trustMarkType = payload.id as string | undefined;
			if (Object.keys(trustMarkIssuers).length === 0 && trustMarkType) {
				trustMarkIssuers = { [trustMarkType]: [payload.iss] };
			}

			// 4. Validate
			const result = await validateTrustMark(trustMarkJwt, trustMarkIssuers, issuerJwks as JWKSet);
			if (result.ok) {
				setDetails(result.value);
				// Check if expired
				if (
					result.value.expiresAt != null &&
					result.value.expiresAt < Math.floor(Date.now() / 1000)
				) {
					setStatus("expired");
				} else {
					setStatus("valid");
				}
			} else {
				const desc = result.error.description;
				if (desc.toLowerCase().includes("expired") || desc.toLowerCase().includes("exp")) {
					setStatus("expired");
				} else {
					setStatus("invalid");
				}
				setError(desc);
			}
		};

		run().catch((err: unknown) => {
			setStatus("error");
			setError(err instanceof Error ? err.message : "Unknown error");
		});
	}, [trustMarkJwt, settings.trustAnchors, settings.httpTimeoutMs]);

	return { status, details, error, verify };
}
