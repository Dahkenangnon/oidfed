import type { MetadataPolicyOptions } from "../metadata-policy/index.js";
import {
	type EntityStatementExtensions,
	prepareEntityStatementExtensions,
	validateSubordinateStatementPublicationClaims,
} from "../statement-builders.js";
import type { SubordinateRecord } from "./subordinates.js";

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
