import { FederationErrorCode } from "../constants.js";
import { err, ok, type Result } from "../errors.js";
import { splitInformationalClaim } from "../language-tags.js";
import {
	COLLECTION_INFO_CLAIMS,
	type EntityCollectionEntity,
	type EntityCollectionRequestParams,
	EntityCollectionRequestSchema,
} from "../schemas/entity-collection.js";

export const COLLECTION_PARAMETERS = {
	from: "from",
	limit: "limit",
	trust_anchor: "trustAnchor",
	entity_type: "entityType",
	trust_mark_type: "trustMarkType",
	query: "query",
	entity_claims: "entityClaims",
	info_claims: "infoClaims",
	locale: "locale",
} as const;
const repeated = new Set([
	"entity_type",
	"trust_mark_type",
	"entity_claims",
	"info_claims",
	"locale",
]);

export function parseCollectionParams(
	form: URLSearchParams,
): Result<EntityCollectionRequestParams> {
	const input: Record<string, unknown> = {};
	for (const name of new Set(form.keys())) {
		// Federation §8 requires unrecognized extension parameters to be ignored.
		if (!Object.hasOwn(COLLECTION_PARAMETERS, name)) continue;
		const key = COLLECTION_PARAMETERS[name as keyof typeof COLLECTION_PARAMETERS];
		const values = form.getAll(name);
		if (!repeated.has(name) && values.length !== 1)
			return err({
				code: FederationErrorCode.InvalidRequest,
				description: `Parameter ${name} must occur once`,
			});
		if (name === "limit") {
			if (!/^[0-9]+$/.test(values[0] ?? ""))
				return err({
					code: FederationErrorCode.InvalidRequest,
					description: "limit must be a nonnegative safe integer",
				});
			input[key] = Number(values[0]);
		} else input[key] = repeated.has(name) ? values : values[0];
	}
	const parsed = EntityCollectionRequestSchema.safeParse(input);
	return parsed.success
		? ok(parsed.data)
		: err({
				code: FederationErrorCode.InvalidRequest,
				description: "Invalid collection request parameters",
			});
}

export function serializeCollectionParams(params: EntityCollectionRequestParams): URLSearchParams {
	const form = new URLSearchParams();
	for (const [wire, key] of Object.entries(COLLECTION_PARAMETERS)) {
		const value = params[key as keyof EntityCollectionRequestParams];
		if (value !== undefined)
			for (const item of Array.isArray(value) ? value : [value]) form.append(wire, String(item));
	}
	return form;
}

export function collectionContext(params: EntityCollectionRequestParams): string {
	return JSON.stringify(
		Object.entries(params)
			.filter(([key]) => key !== "from" && key !== "limit")
			.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
			.map(([key, value]) => [key, Array.isArray(value) ? [...new Set(value)].sort() : value]),
	);
}

export function projectCollectionEntity(
	entity: EntityCollectionEntity,
	params: EntityCollectionRequestParams,
	infoClaims: ReadonlySet<string> = new Set(COLLECTION_INFO_CLAIMS),
): EntityCollectionEntity {
	const selected = params.entityClaims;
	const pairs = Object.entries(entity).filter(
		([name]) => name === "entity_id" || selected === undefined || selected.includes(name),
	);
	const result = Object.fromEntries(pairs) as EntityCollectionEntity;
	if (result.entity_infos) {
		result.entity_infos = Object.fromEntries(
			Object.entries(result.entity_infos)
				.filter(
					([type]) =>
						!params.entityType?.length ||
						type === "federation_entity" ||
						params.entityType.includes(type),
				)
				.map(([type, info]) => [
					type,
					Object.fromEntries(
						Object.entries(info).filter(([name]) => {
							const { base, tag } = splitInformationalClaim(name, infoClaims);
							if (
								params.infoClaims !== undefined &&
								!params.infoClaims.includes(name) &&
								!params.infoClaims.includes(base)
							)
								return false;
							return (
								!tag ||
								!params.locale?.length ||
								params.locale.some((locale) => {
									const lower = tag.toLowerCase();
									const range = locale.toLowerCase();
									return lower === range || lower.startsWith(`${range}-`);
								})
							);
						}),
					),
				]),
		);
	}
	return structuredClone(result);
}

export function collectionText(entity: EntityCollectionEntity): string {
	const values = Object.values(entity.entity_infos ?? {}).flatMap((info) =>
		Object.values(info).flatMap((value) =>
			typeof value === "string"
				? [value]
				: Array.isArray(value)
					? value.filter((item): item is string => typeof item === "string")
					: [],
		),
	);
	return [entity.entity_id, ...values].join("\n").toLowerCase();
}
