import { SubordinateStatementSchema, validateRoleMetadata } from "@oidfed/core";
import type { HandlerContext } from "../endpoints/context.js";
import type { SubordinateRecord } from "../storage/types.js";
import {
	assertMetadataValuesNotNull,
	sanitizeSubordinateMetadata,
} from "./subordinate-statement-shape.js";

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
	SubordinateStatementSchema.shape[claim].parse(value);
	if (claim === "metadata") {
		const metadata = value as Record<string, unknown>;
		assertMetadataValuesNotNull(metadata);
		validateRoleMetadata(undefined, metadata, {
			entityId: record.entityId,
			keyProvider: ctx.keyProvider,
		});
	}
	if (claim === "metadata_policy") {
		for (const parameters of Object.values(value as Record<string, Record<string, unknown>>)) {
			for (const operators of Object.values(parameters)) {
				if (!operators || typeof operators !== "object" || Array.isArray(operators))
					throw new TypeError("Metadata policy operators must be objects");
			}
		}
	}
	return structuredClone(value);
}
