/** Protocol checks belong at publication and at the point resolved metadata is used. */
import { err, FederationErrorCode, federationError, ok } from "@oidfed/core";
import {
	effectiveRoleSchemas,
	publicationRoleSchemas,
	rpMetadataChoices,
} from "./schemas/metadata.js";

export type ProtocolEntityType = keyof typeof effectiveRoleSchemas;

export function effectiveMetadata(
	type: ProtocolEntityType,
	metadata: unknown,
	expectedIssuer?: string,
) {
	const parsed = effectiveRoleSchemas[type].safeParse(metadata);
	if (
		parsed.success &&
		expectedIssuer !== undefined &&
		(type === "openid_provider" || type === "oauth_authorization_server") &&
		parsed.data.issuer !== expectedIssuer
	)
		return err(
			federationError(
				FederationErrorCode.InvalidMetadata,
				`${type}.issuer MUST match the Entity Identifier`,
			),
		);
	return parsed.success
		? ok(parsed.data)
		: err(
				federationError(
					FederationErrorCode.InvalidMetadata,
					`Invalid ${type} metadata: ${parsed.error.issues.map((issue) => `${issue.path.join(".")}: ${issue.message}`).join("; ")}`,
				),
			);
}

export function assertPublicationMetadata(type: ProtocolEntityType, metadata: unknown): void {
	const parsed = publicationRoleSchemas[type].safeParse(metadata);
	if (!parsed.success)
		throw new TypeError(
			`Invalid ${type} publication metadata: ${parsed.error.issues.map((issue) => `${issue.path.join(".")}: ${issue.message}`).join("; ")}`,
		);
}

/** Check protocol-engine selections before removing registration-input-only fields. */
export function registrationResponseChoices(
	metadata: Record<string, unknown>,
	input: Record<string, unknown>,
) {
	const defaults: Record<string, unknown> = {
		id_token_signed_response_alg: "RS256",
		token_endpoint_auth_method: "client_secret_basic",
	};
	for (const [plural, singular] of Object.entries(rpMetadataChoices)) {
		const choices = input[plural];
		const selected = metadata[singular] ?? defaults[singular];
		if (Array.isArray(choices) && selected !== undefined && !choices.includes(selected))
			return err(
				federationError(
					FederationErrorCode.InvalidMetadata,
					`${singular} MUST be included in the RP's ${plural}`,
				),
			);
	}
	return ok(undefined);
}

export function withoutRegistrationChoices(metadata: Record<string, unknown>) {
	const output = { ...metadata };
	for (const field of Object.keys(rpMetadataChoices)) delete output[field];
	return output;
}
