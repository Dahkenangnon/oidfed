import { InternalErrorCode } from "../constants.js";
import type { ParsedEntityStatement, ValidationError } from "../types.js";

/** Only call when the entity is known to act as an authority in the current path. */
export function authorityMetadataErrors(statement: ParsedEntityStatement): ValidationError[] {
	const metadata = statement.payload.metadata?.federation_entity;
	return ["federation_fetch_endpoint", "federation_list_endpoint"]
		.filter((parameter) => typeof metadata?.[parameter] !== "string")
		.map((parameter) => ({
			code: InternalErrorCode.TrustChainInvalid,
			message: `Authority '${statement.payload.sub}' MUST publish ${parameter}`,
			field: `metadata.federation_entity.${parameter}`,
			checkNumber: 16,
		}));
}
