/** Zod schema for federation metadata policy: operator constraints applied during trust chain resolution. */
import { z } from "zod";

const jsonObject = z.record(z.string(), z.unknown());
const metadataValue = z.union([z.string(), z.number(), z.boolean(), z.array(z.unknown())]);
const comparableValue = z.union([z.string(), z.number(), jsonObject]);
const comparableArray = z.array(comparableValue);

export const MetadataParameterPolicySchema = z.looseObject({
	value: z.union([metadataValue, z.null()]).optional(),
	add: comparableArray.optional(),
	default: metadataValue.optional(),
	one_of: comparableArray.optional(),
	subset_of: comparableArray.optional(),
	superset_of: comparableArray.optional(),
	essential: z.boolean().optional(),
});

export const EntityTypeMetadataPolicySchema = z.record(z.string(), MetadataParameterPolicySchema);

export const FederationMetadataPolicySchema = z.record(z.string(), EntityTypeMetadataPolicySchema);

export type MetadataParameterPolicy = z.infer<typeof MetadataParameterPolicySchema>;
export type EntityTypeMetadataPolicy = z.infer<typeof EntityTypeMetadataPolicySchema>;
export type FederationMetadataPolicy = z.infer<typeof FederationMetadataPolicySchema>;
