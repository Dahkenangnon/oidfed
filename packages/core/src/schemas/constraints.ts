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
	allowed_entity_types: z
		.array(
			z.enum([
				"openid_relying_party",
				"openid_provider",
				"oauth_authorization_server",
				"oauth_client",
				"oauth_resource",
			]),
		)
		.optional(),
});

export type NamingConstraints = z.infer<typeof NamingConstraintsSchema>;
export type TrustChainConstraints = z.infer<typeof TrustChainConstraintsSchema>;
