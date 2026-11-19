/** Evaluation of published Trust Marks using configured issuer trust evidence. */

import { InternalErrorCode } from "../constants.js";
import { decodeEntityStatement } from "../jose/verify.js";
import type { JWKSet } from "../schemas/jwk.js";
import type { TrustMarkOwner } from "../schemas/trust-mark.js";
import type {
	FederationOptions,
	ParsedEntityStatement,
	TrustAnchorSet,
	TrustMarkEvaluation,
} from "../types.js";
import { validateTrustMarkWithIssuer } from "./evidence.js";
import { validateTrustMark } from "./index.js";
import { createConfiguredTrustMarkIssuerResolver } from "./issuer-selection.js";

/** Evaluate subject marks using evidence authenticated by chain validation or the caller. */
export async function evaluatePublishedTrustMarks(
	statements: readonly ParsedEntityStatement[],
	anchors: TrustAnchorSet,
	options: FederationOptions & { trustMarkIssuerKeys?: ReadonlyMap<string, JWKSet> },
	evaluate: boolean,
): Promise<TrustMarkEvaluation[]> {
	const subject = statements[0]?.payload;
	const root = statements[statements.length - 1]?.payload;
	if (!subject || !root) return [];
	const refs = subject.trust_marks ?? [];
	const issuers = root.iss === root.sub ? root.trust_mark_issuers : undefined;
	const owners = root.iss === root.sub ? root.trust_mark_owners : undefined;
	const keys = new Map<string, JWKSet>();
	const anchor = anchors.get(root.iss);
	if (anchor) keys.set(root.iss, anchor.jwks);
	for (const statement of statements) {
		if (statement.payload.iss === statement.payload.sub && statement.payload.jwks) {
			keys.set(statement.payload.iss, statement.payload.jwks);
		}
	}
	const results: TrustMarkEvaluation[] = [];
	const resolveIssuer = createConfiguredTrustMarkIssuerResolver(anchors, options);
	for (const [referenceIndex, ref] of refs.entries()) {
		const reference = { referenceIndex, trustMarkType: ref.trust_mark_type };
		const invalid = (description: string): TrustMarkEvaluation => ({
			...reference,
			status: "invalid",
			error: { code: InternalErrorCode.TrustMarkInvalid, description },
		});
		if (!evaluate) {
			results.push({
				...reference,
				status: "unevaluated",
				reason: "not_evaluated",
				description: "Trust Mark evaluation is handled separately",
			});
			continue;
		}
		if (options?.trustMarkVerification) {
			const decoded = decodeEntityStatement(ref.trust_mark, options);
			if (!decoded.ok) {
				results.push(invalid(decoded.error.description));
				continue;
			}
			const issuer = decoded.value.payload.iss;
			const config = options.trustMarkVerification;
			const proof = resolveIssuer(issuer, ref.trust_mark_type);
			if (!proof) {
				results.push({
					...reference,
					status: "unevaluated",
					reason: "issuer_keys_unavailable",
					description: "No trusted issuer evidence supplied for this Trust Mark",
				});
				continue;
			}
			const established = await proof;
			if (!established.ok) {
				results.push(invalid(established.error.description));
				continue;
			}
			const checked = await validateTrustMarkWithIssuer(ref.trust_mark, established.value, {
				...options,
				expectedSubject: subject.iss,
				expectedTrustMarkType: ref.trust_mark_type,
				...(config.historicalKeys ? { historicalKeys: config.historicalKeys } : {}),
			});
			results.push(
				checked.ok
					? { ...reference, status: "verified", mark: checked.value }
					: { ...reference, status: "invalid", error: checked.error },
			);
			continue;
		}
		if (!issuers || !Object.hasOwn(issuers, ref.trust_mark_type)) {
			results.push({
				...reference,
				status: "unevaluated",
				reason: "issuer_policy_unavailable",
				description: "No issuer declaration is available for this Trust Mark type",
			});
			continue;
		}
		const allowed = issuers[ref.trust_mark_type];
		if (!Array.isArray(allowed) || !allowed.every((issuer) => typeof issuer === "string")) {
			results.push(invalid("Trust Mark issuer entry must be an array of Entity Identifiers"));
			continue;
		}
		const decoded = decodeEntityStatement(ref.trust_mark, options);
		if (!decoded.ok) {
			results.push(invalid(decoded.error.description));
			continue;
		}
		const issuer = decoded.value.payload.iss;
		if (typeof issuer !== "string") {
			results.push(invalid("Trust Mark issuer must be an Entity Identifier"));
			continue;
		}
		if (allowed.length > 0 && !allowed.includes(issuer)) {
			results.push(invalid("Issuer is not authorized for this trust mark type"));
			continue;
		}
		const issuerKeys = options?.trustMarkIssuerKeys?.get(issuer) ?? keys.get(issuer);
		if (!issuerKeys) {
			results.push({
				...reference,
				status: "unevaluated",
				reason: "issuer_keys_unavailable",
				description: `No independently trusted federation keys are available for issuer '${issuer}'`,
			});
			continue;
		}
		const checked = await validateTrustMark(ref.trust_mark, issuers, issuerKeys, {
			...options,
			expectedSubject: subject.iss,
			expectedTrustMarkType: ref.trust_mark_type,
			...(owners ? { trustMarkOwners: owners as Record<string, TrustMarkOwner> } : {}),
		});
		results.push(
			checked.ok
				? { ...reference, status: "verified", mark: checked.value }
				: { ...reference, status: "invalid", error: checked.error },
		);
	}
	return results;
}
