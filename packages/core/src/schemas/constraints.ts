/** Zod schema for naming_constraints: allowed/denied entity ID patterns for subordinate statements. */
import { z } from "zod";

const domainPattern = z
	.string()
	.min(1)
	.refine((val) => !val.includes("*") && !val.includes("?"), {
		message: 'Wildcard patterns not allowed; use ".example.com" for subdomain matching',
	});

export const NamingConstraintsSchema = z.object({
	permitted: z.array(domainPattern).optional(),
	excluded: z.array(domainPattern).optional(),
});

export const TrustChainConstraintsSchema = z.looseObject({
	max_path_length: z.number().int().nonnegative().max(100).optional(),
	naming_constraints: NamingConstraintsSchema.optional(),
	// Federation §§5.1 and 6.2.3: custom types are valid; federation_entity is implicit.
	allowed_entity_types: z
		.array(
			z
				.string()
				.min(1)
				.refine((type) => type !== "federation_entity", {
					message: "federation_entity must not appear in allowed_entity_types",
				}),
		)
		.optional(),
});

export type NamingConstraints = z.infer<typeof NamingConstraintsSchema>;
export type TrustChainConstraints = z.infer<typeof TrustChainConstraintsSchema>;
