/** Zod schema for naming_constraints: allowed/denied entity ID patterns for subordinate statements. */
import { z } from "zod";

/** RFC 5280 URI constraints use DNS host/domain names, never URL or IP patterns. */
export function isDomainConstraint(value: string): boolean {
	const domain = value.replace(/^\./, "").replace(/\.$/, "");
	if (!domain || domain.length > 253 || /^[0-9.]+$/.test(domain)) return false;
	return domain
		.split(".")
		.every((label) => label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label));
}

const domainPattern = z.string().refine(isDomainConstraint, {
	message:
		'Naming constraints must be DNS host names or domains; use ".example.com" for subdomains',
});

export const NamingConstraintsSchema = z.object({
	permitted: z.array(domainPattern).optional(),
	excluded: z.array(domainPattern).optional(),
});

export const TrustChainConstraintsSchema = z.looseObject({
	max_path_length: z.number().int().nonnegative().optional(),
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
