/** Subordinate publication-claim validation shared by write and signing paths. */

import {
	type EntityStatementExtensions,
	type MetadataPolicyOptions,
	prepareEntityStatementExtensions,
	validateRoleMetadata,
	validateSubordinateStatementPublicationClaims,
} from "@oidfed/core";
import type { HandlerContext } from "../endpoints/context.js";
import type { SubordinateRecord } from "../storage/types.js";
import {
	assertMetadataValuesNotNull,
	sanitizeSubordinateMetadata,
} from "./subordinate-statement-shape.js";

/** The record projection is also used before lifecycle writes and direct memory-store writes. */
export function assertSubordinatePublicationClaims(
	record: {
		[K in keyof Pick<
			SubordinateRecord,
			| "metadata"
			| "metadataPolicy"
			| "constraints"
			| "sourceEndpoint"
			| "additionalClaims"
			| "crit"
			| "metadataPolicyCrit"
		>]: SubordinateRecord[K] | undefined;
	},
	options?: MetadataPolicyOptions,
): void {
	let extensions: EntityStatementExtensions;
	try {
		extensions = prepareEntityStatementExtensions(record);
	} catch (error) {
		throw new TypeError(
			`Invalid Subordinate Statement: ${error instanceof Error ? error.message : "invalid extensions"}`,
		);
	}
	const payload = {
		...extensions.additionalClaims,
		...Object.fromEntries<unknown>(
			(
				[
					["metadata", record.metadata],
					["metadata_policy", record.metadataPolicy],
					["constraints", record.constraints],
					["source_endpoint", record.sourceEndpoint],
					["crit", extensions.crit],
					["metadata_policy_crit", record.metadataPolicyCrit],
				] as const
			).filter(([, value]) => value !== undefined),
		),
	};
	const valid = validateSubordinateStatementPublicationClaims(payload, options);
	if (!valid.ok) throw new TypeError(valid.error.description);
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
			keyProvider: ctx.keyProvider,
		});
	}
	return structuredClone(value);
}
