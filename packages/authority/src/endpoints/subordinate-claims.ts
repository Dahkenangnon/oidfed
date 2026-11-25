import { cloneData } from "@oidfed/core";

/** Validate subordinate publication claims for Fetch and Extended Listing. */

import type { SubordinateRecord } from "@oidfed/core";
import {
	assertMetadataValuesNotNull,
	sanitizeSubordinateMetadata,
	validateRoleMetadata,
	validateSubordinateStatementPublicationClaims,
} from "@oidfed/core";
import type { HandlerContext } from "./context.js";

/** Compare JSON data independently of object member order. Array order remains significant. */
export function canonicalSubordinateJson(value: unknown): string {
	if (Array.isArray(value)) return `[${value.map(canonicalSubordinateJson).join(",")}]`;
	if (value && typeof value === "object") {
		return `{${Object.entries(value)
			.filter(([, member]) => member !== undefined)
			.sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
			.map(([name, member]) => `${JSON.stringify(name)}:${canonicalSubordinateJson(member)}`)
			.join(",")}}`;
	}
	return JSON.stringify(value) ?? "undefined";
}

/** Validate only the selected public claim, shared by signed fetch and Extended Listing §3.2. */
export function subordinatePublicationClaim(
	record: SubordinateRecord,
	claim: "metadata" | "metadata_policy" | "constraints",
	ctx: HandlerContext,
): unknown {
	const value =
		claim === "metadata"
			? sanitizeSubordinateMetadata(record.metadata)
			: claim === "metadata_policy"
				? record.metadataPolicy
				: record.constraints;
	if (value === undefined) return undefined;
	const valid = validateSubordinateStatementPublicationClaims(
		{ [claim]: value },
		{ customOperators: ctx.options?.customPolicyOperators },
	);
	if (!valid.ok) throw new TypeError(valid.error.description);
	if (claim === "metadata") {
		const metadata = value as Record<string, unknown>;
		assertMetadataValuesNotNull(metadata);
		validateRoleMetadata(undefined, metadata, {
			entityId: record.entityId,
			crypto: ctx.crypto,
			options: ctx.options,
		});
	}
	return cloneData(value);
}
