/** Zod schema for federation metadata policy: operator constraints applied during trust chain resolution. */
import { z } from "zod";

export const MetadataParameterPolicySchema = z.looseObject({
	value: z.unknown().optional(),
	add: z.unknown().optional(),
	default: z.unknown().optional(),
	one_of: z.array(z.unknown()).optional(),
	subset_of: z.array(z.unknown()).optional(),
	superset_of: z.array(z.unknown()).optional(),
	essential: z.boolean().optional(),
});

export const EntityTypeMetadataPolicySchema = z.record(z.string(), MetadataParameterPolicySchema);

export const FederationMetadataPolicySchema = z.record(z.string(), EntityTypeMetadataPolicySchema);

export type MetadataParameterPolicy = z.infer<typeof MetadataParameterPolicySchema>;
export type EntityTypeMetadataPolicy = z.infer<typeof EntityTypeMetadataPolicySchema>;
export type FederationMetadataPolicy = z.infer<typeof FederationMetadataPolicySchema>;
