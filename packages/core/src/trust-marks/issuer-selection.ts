/** Configured issuer-evidence selection shared by Trust Mark consumers. */

import { ok, type Result } from "../errors.js";
import type { FederationOptions, TrustAnchorSet } from "../types.js";
import { establishTrustMarkIssuerTrust, type TrustMarkIssuerContext } from "./evidence.js";

/** Operation-local evidence lookup shared by chain and collection verification. */
export function createConfiguredTrustMarkIssuerResolver(
	anchors: TrustAnchorSet,
	options: FederationOptions,
) {
	const evidence = new Map<string, Promise<Result<TrustMarkIssuerContext>>>();
	return (
		issuer: string,
		trustMarkType: string,
	): Promise<Result<TrustMarkIssuerContext>> | undefined => {
		const config = options?.trustMarkVerification;
		if (!config) return undefined;
		const identity = JSON.stringify([issuer, trustMarkType]);
		const existing = evidence.get(identity);
		if (existing) return existing;
		const matching = config.issuerEvidence?.find(
			(context) =>
				context.issuer === issuer &&
				(context.kind === "federation"
					? context.trustMarkType === trustMarkType
					: context.allowedTrustMarkTypes.includes(trustMarkType)),
		);
		const proof = matching
			? Promise.resolve(ok(matching))
			: config.mode === "resolve"
				? establishTrustMarkIssuerTrust({
						issuer,
						trustMarkType,
						trustAnchors: config.trustAnchors ?? anchors,
						options,
					})
				: undefined;
		if (proof) evidence.set(identity, proof);
		return proof;
	};
}
