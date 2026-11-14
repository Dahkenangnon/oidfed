import {
	oauthRegistrationSchemas,
	oidcRegistrationSchemas,
} from "../schemas/explicit-registration.js";
import {
	effectiveRoleSchemas,
	OAuthClientRegistrationResponseMetadataSchema,
	OpenIDRelyingPartyRegistrationResponseMetadataSchema,
} from "../schemas/metadata.js";

/** Roles select a profile explicitly; co-published metadata cannot change the protocol. */
export const oidcRegistrationProfile = {
	clientType: "openid_relying_party",
	providerType: "openid_provider",
	oidc: true,
	clientSchema: effectiveRoleSchemas.openid_relying_party,
	responseMetadataSchema: OpenIDRelyingPartyRegistrationResponseMetadataSchema,
	...oidcRegistrationSchemas,
} as const;
export const oauthRegistrationProfile = {
	clientType: "oauth_client",
	providerType: "oauth_authorization_server",
	oidc: false,
	clientSchema: effectiveRoleSchemas.oauth_client,
	responseMetadataSchema: OAuthClientRegistrationResponseMetadataSchema,
	...oauthRegistrationSchemas,
} as const;
export type RegistrationProfile = typeof oidcRegistrationProfile | typeof oauthRegistrationProfile;
export function registrationProfile(
	providerType: RegistrationProfile["providerType"] = "openid_provider",
): RegistrationProfile {
	return providerType === "oauth_authorization_server"
		? oauthRegistrationProfile
		: oidcRegistrationProfile;
}
