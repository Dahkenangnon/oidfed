# Metadata and wire types

[`@oidfed/oidc`](README.md)

These are exported TypeScript types, not schema objects. Validate individual metadata blocks through the matching role's `parseMetadata` or `parsePublicationMetadata` method. Successful parsing checks data and cross-field rules; Federation signature, issuer binding, and trust checks belong to the consuming workflow.

Publication metadata can omit requirements supplied later by a Superior. Effective metadata must satisfy those requirements after completion. Registration response types separately permit credential fields that cannot be published in client EC metadata. Conditional runtime requirements can apply even to fields marked optional in TypeScript.

Known fields are typed and extension fields are preserved as unknown data. The expanded declarations below use public type names; `z.output<typeof EntityIdSchema>` refers to core's Zod-branded identifier, distinct from its `EntityId` factory brand. Long declarations can be expanded when needed; field tables remain visible.

## `ExplicitRegistrationRequestPayload`

[Source](../../../packages/oidc/src/schemas/explicit-registration.ts#L107)

Exported OIDC explicit-registration EC envelope type. It includes a self-issued client identity, intended provider audience, Federation public keys, nonempty Superior hints, and metadata containing openid_relying_party. The OAuth role uses a corresponding internal OAuth envelope; this export is the OIDC form. Parsing and complete cryptographic registration checks are separate.

```typescript signature
type ExplicitRegistrationRequestPayload = {
	[key: string]: unknown;
	iss: z.output<typeof EntityIdSchema>;
	sub: z.output<typeof EntityIdSchema>;
	aud: string;
	iat: number;
	exp: number;
	jwks: JWKSet;
	authority_hints: Array<z.output<typeof EntityIdSchema>>;
	metadata: FederationMetadata;
	trust_marks?: undefined | Array<TrustMarkRef>;
};
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `iss` | `z.output<typeof EntityIdSchema>` | Client Entity Identifier signing the self-issued registration EC. |
| `sub` | `z.output<typeof EntityIdSchema>` | Client subject; the request requires sub to equal iss. |
| `aud` | `string` | Intended provider Entity Identifier; the registration receiver verifies the exact match. |
| `iat` | `number` | Issuance time as a finite NumericDate in seconds since the Unix epoch. |
| `exp` | `number` | Expiration time as a finite NumericDate in seconds since the Unix epoch. |
| `jwks` | `JWKSet` | Client Federation Entity Keys, not the application protocol key set. |
| `authority_hints` | `Array<z.output<typeof EntityIdSchema>>` | Entity Identifiers of Immediate Superiors from which a chain may be built. |
| `metadata` | `FederationMetadata` | Entity Type metadata map containing openid_relying_party for this exported OIDC envelope type. |
| `trust_marks?` | `undefined \| Array<TrustMarkRef>` | Published Trust Mark references or resolver-reported assessments, according to this artifact's schema. |

## `ExplicitRegistrationResponsePayload`

[Source](../../../packages/oidc/src/schemas/explicit-registration.ts#L110)

Exported OIDC registration-response envelope type. The provider identifies the client as subject and audience, carries exactly one Immediate Superior hint and the selected anchor, and places credentials inside metadata.openid_relying_party. The OAuth profile uses a separate internal envelope. Its JWT signature, recipient, times, and metadata policy must also be verified.

```typescript signature
type ExplicitRegistrationResponsePayload = {
	[key: string]: unknown;
	iss: z.output<typeof EntityIdSchema>;
	sub: z.output<typeof EntityIdSchema>;
	aud: string;
	iat: number;
	exp: number;
	metadata: Record<string, Record<string, unknown>>;
	trust_anchor: z.output<typeof EntityIdSchema>;
	authority_hints: Array<z.output<typeof EntityIdSchema>>;
};
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `iss` | `z.output<typeof EntityIdSchema>` | Provider Entity Identifier issuing the registration response. |
| `sub` | `z.output<typeof EntityIdSchema>` | Registered client Entity Identifier. |
| `aud` | `string` | Client Entity Identifier receiving this registration response. |
| `iat` | `number` | Issuance time as a finite NumericDate in seconds since the Unix epoch. |
| `exp` | `number` | Expiration time as a finite NumericDate in seconds since the Unix epoch. |
| `metadata` | `Record<string, Record<string, unknown>>` | Registration response metadata map containing an OIDC client block; credentials belong inside that block. |
| `trust_anchor` | `z.output<typeof EntityIdSchema>` | Trust Anchor selected for the client registration chain. |
| `authority_hints` | `Array<z.output<typeof EntityIdSchema>>` | Exactly one identifier: the client's Immediate Superior in the selected chain. |

## `OAuthAuthorizationServerMetadata`

[Source](../../../packages/oidc/src/schemas/metadata.ts#L441)

Effective AS metadata type shared structurally with core's RFC 8414 parser. OAuthAuthorizationServerRole.parseMetadata checks the complete object, including conditional endpoints and attestation requirements. Standalone parsing does not establish issuer trust, bind it to a known Entity Identifier, or authenticate signed_metadata.

<details>
<summary>Type declaration</summary>

```typescript signature
type OAuthAuthorizationServerMetadata = {
	[key: string]: unknown;
	issuer: string;
	response_types_supported: Array<string>;
	authorization_endpoint?: undefined | string;
	token_endpoint?: undefined | string;
	response_modes_supported?: undefined | Array<string>;
	grant_types_supported?: undefined | Array<string>;
	scopes_supported?: undefined | Array<string>;
	jwks_uri?: undefined | string;
	signed_jwks_uri?: undefined | string;
	jwks?: undefined | { [key: string]: unknown; keys: Array<JWK>; };
	registration_endpoint?: undefined | string;
	token_endpoint_auth_methods_supported?: undefined | Array<string>;
	client_attestation_signing_alg_values_supported?: undefined | Array<string>;
	client_attestation_pop_signing_alg_values_supported?: undefined | Array<string>;
	challenge_endpoint?: undefined | string;
	token_endpoint_auth_signing_alg_values_supported?: undefined | Array<string>;
	revocation_endpoint?: undefined | string;
	revocation_endpoint_auth_methods_supported?: undefined | Array<string>;
	revocation_endpoint_auth_signing_alg_values_supported?: undefined | Array<string>;
	introspection_endpoint?: undefined | string;
	introspection_endpoint_auth_methods_supported?: undefined | Array<string>;
	introspection_endpoint_auth_signing_alg_values_supported?: undefined | Array<string>;
	introspection_signing_alg_values_supported?: undefined | Array<string>;
	introspection_encryption_alg_values_supported?: undefined | Array<string>;
	introspection_encryption_enc_values_supported?: undefined | Array<string>;
	userinfo_endpoint?: undefined | string;
	acr_values_supported?: undefined | Array<string>;
	subject_types_supported?: undefined | Array<string>;
	id_token_signing_alg_values_supported?: undefined | Array<string>;
	id_token_encryption_alg_values_supported?: undefined | Array<string>;
	id_token_encryption_enc_values_supported?: undefined | Array<string>;
	userinfo_signing_alg_values_supported?: undefined | Array<string>;
	userinfo_encryption_alg_values_supported?: undefined | Array<string>;
	userinfo_encryption_enc_values_supported?: undefined | Array<string>;
	request_object_signing_alg_values_supported?: undefined | Array<string>;
	request_object_encryption_alg_values_supported?: undefined | Array<string>;
	request_object_encryption_enc_values_supported?: undefined | Array<string>;
	display_values_supported?: undefined | Array<string>;
	claim_types_supported?: undefined | Array<string>;
	claims_supported?: undefined | Array<string>;
	claims_locales_supported?: undefined | Array<string>;
	claims_parameter_supported?: undefined | boolean;
	request_parameter_supported?: undefined | boolean;
	request_uri_parameter_supported?: undefined | boolean;
	require_request_uri_registration?: undefined | boolean;
	check_session_iframe?: undefined | string;
	frontchannel_logout_supported?: undefined | boolean;
	frontchannel_logout_session_supported?: undefined | boolean;
	backchannel_logout_supported?: undefined | boolean;
	backchannel_logout_session_supported?: undefined | boolean;
	end_session_endpoint?: undefined | string;
	backchannel_token_delivery_modes_supported?: undefined | Array<"push" | "poll" | "ping">;
	backchannel_authentication_endpoint?: undefined | string;
	backchannel_authentication_request_signing_alg_values_supported?: undefined | Array<string>;
	backchannel_user_code_parameter_supported?: undefined | boolean;
	authorization_signing_alg_values_supported?: undefined | Array<string>;
	authorization_encryption_alg_values_supported?: undefined | Array<string>;
	authorization_encryption_enc_values_supported?: undefined | Array<string>;
	nfv_token_signing_alg_values_supported?: undefined | Array<string>;
	nfv_token_encryption_alg_values_supported?: undefined | Array<string>;
	nfv_token_encryption_enc_values_supported?: undefined | Array<string>;
	code_challenge_methods_supported?: undefined | Array<string>;
	device_authorization_endpoint?: undefined | string;
	pushed_authorization_request_endpoint?: undefined | string;
	require_pushed_authorization_requests?: undefined | boolean;
	require_signed_request_object?: undefined | boolean;
	dpop_signing_alg_values_supported?: undefined | Array<string>;
	authorization_response_iss_parameter_supported?: undefined | boolean;
	authorization_details_types_supported?: undefined | Array<string>;
	protected_resources?: undefined | Array<string>;
	tls_client_certificate_bound_access_tokens?: undefined | boolean;
	mtls_endpoint_aliases?: undefined | { [key: string]: unknown; token_endpoint?: undefined | string; revocation_endpoint?: undefined | string; introspection_endpoint?: undefined | string; device_authorization_endpoint?: undefined | string; pushed_authorization_request_endpoint?: undefined | string; userinfo_endpoint?: undefined | string; backchannel_authentication_endpoint?: undefined | string; };
	signed_metadata?: undefined | string;
	service_documentation?: undefined | string;
	ui_locales_supported?: undefined | Array<string>;
	op_policy_uri?: undefined | string;
	op_tos_uri?: undefined | string;
	organization_name?: undefined | string;
	display_name?: undefined | string;
	description?: undefined | string;
	keywords?: undefined | Array<string>;
	contacts?: undefined | Array<string>;
	logo_uri?: undefined | string;
	policy_uri?: undefined | string;
	information_uri?: undefined | string;
	organization_uri?: undefined | string;
	organization_identifier?: undefined | string;
	client_registration_types_supported?: undefined | Array<string>;
	federation_registration_endpoint?: undefined | string;
};
```

</details>

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `issuer` | `string` | Protocol issuer URL. Federation consumers additionally bind it to the Entity Identifier. |
| `response_types_supported` | `Array<string>` | Supported OAuth response types; required for the normal effective AS profile. |
| `authorization_endpoint?` | `undefined \| string` | HTTPS endpoint for authorization requests; no fragment is allowed. |
| `token_endpoint?` | `undefined \| string` | HTTPS token endpoint; required in effective metadata unless only implicit is supported. |
| `response_modes_supported?` | `undefined \| Array<string>` | Supported authorization response modes. |
| `grant_types_supported?` | `undefined \| Array<string>` | Supported OAuth grant types; omitted values use the protocol's default when evaluating conditional requirements. |
| `scopes_supported?` | `undefined \| Array<string>` | Supported OAuth scopes. |
| `jwks_uri?` | `undefined \| string` | HTTPS URL for public protocol keys, without a fragment. |
| `signed_jwks_uri?` | `undefined \| string` | HTTPS URL for a signed protocol JWK Set, without a fragment. |
| `jwks?` | `undefined \| { [key: string]: unknown; keys: Array<JWK>; }` | JSON Web Key Set. The owning API determines whether these are Federation Entity Keys or protocol keys. |
| `registration_endpoint?` | `undefined \| string` | HTTPS dynamic client registration endpoint. |
| `token_endpoint_auth_methods_supported?` | `undefined \| Array<string>` | Supported authentication methods for token endpoint. |
| `client_attestation_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted client attestation signing algorithms. Parsing applies this field's protocol restrictions. |
| `client_attestation_pop_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted client attestation pop signing algorithms. Parsing applies this field's protocol restrictions. |
| `challenge_endpoint?` | `undefined \| string` | Client-attestation challenge endpoint URL; this schema checks URL syntax, not endpoint trust. |
| `token_endpoint_auth_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted token endpoint auth signing algorithms. Parsing applies this field's protocol restrictions. |
| `revocation_endpoint?` | `undefined \| string` | HTTPS endpoint for token revocation. |
| `revocation_endpoint_auth_methods_supported?` | `undefined \| Array<string>` | Supported authentication methods for revocation endpoint. |
| `revocation_endpoint_auth_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted revocation endpoint auth signing algorithms. Parsing applies this field's protocol restrictions. |
| `introspection_endpoint?` | `undefined \| string` | HTTPS endpoint for token introspection. |
| `introspection_endpoint_auth_methods_supported?` | `undefined \| Array<string>` | Supported authentication methods for introspection endpoint. |
| `introspection_endpoint_auth_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted introspection endpoint auth signing algorithms. Parsing applies this field's protocol restrictions. |
| `introspection_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted introspection signing algorithms. Parsing applies this field's protocol restrictions. |
| `introspection_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted introspection encryption algorithms. Parsing applies this field's protocol restrictions. |
| `introspection_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted introspection encryption content-encryption methods. |
| `userinfo_endpoint?` | `undefined \| string` | HTTPS OpenID Connect UserInfo endpoint. |
| `acr_values_supported?` | `undefined \| Array<string>` | Supported authentication context class reference values. |
| `subject_types_supported?` | `undefined \| Array<string>` | Supported OpenID Connect subject identifier types. |
| `id_token_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted id token signing algorithms. Parsing applies this field's protocol restrictions. |
| `id_token_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted id token encryption algorithms. Parsing applies this field's protocol restrictions. |
| `id_token_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted id token encryption content-encryption methods. |
| `userinfo_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted userinfo signing algorithms. Parsing applies this field's protocol restrictions. |
| `userinfo_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted userinfo encryption algorithms. Parsing applies this field's protocol restrictions. |
| `userinfo_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted userinfo encryption content-encryption methods. |
| `request_object_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted request object signing algorithms. Parsing applies this field's protocol restrictions. |
| `request_object_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted request object encryption algorithms. Parsing applies this field's protocol restrictions. |
| `request_object_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted request object encryption content-encryption methods. |
| `display_values_supported?` | `undefined \| Array<string>` | Supported OpenID Connect display modes. |
| `claim_types_supported?` | `undefined \| Array<string>` | Supported OpenID Connect claim representations. |
| `claims_supported?` | `undefined \| Array<string>` | Supported claim names. |
| `claims_locales_supported?` | `undefined \| Array<string>` | Supported languages for returned claims. |
| `claims_parameter_supported?` | `undefined \| boolean` | Whether the OpenID Connect claims request parameter is supported. |
| `request_parameter_supported?` | `undefined \| boolean` | Whether a Request Object can be sent using the request parameter. |
| `request_uri_parameter_supported?` | `undefined \| boolean` | Whether Request Objects can be referenced using request_uri. |
| `require_request_uri_registration?` | `undefined \| boolean` | Whether Request Object URIs must be registered in advance. |
| `check_session_iframe?` | `undefined \| string` | HTTPS session-management iframe URL. |
| `frontchannel_logout_supported?` | `undefined \| boolean` | Whether front-channel logout is supported. |
| `frontchannel_logout_session_supported?` | `undefined \| boolean` | Whether front-channel logout supports session identifiers. |
| `backchannel_logout_supported?` | `undefined \| boolean` | Whether back-channel logout is supported. |
| `backchannel_logout_session_supported?` | `undefined \| boolean` | Whether back-channel logout supports session identifiers. |
| `end_session_endpoint?` | `undefined \| string` | HTTPS endpoint for initiating logout. |
| `backchannel_token_delivery_modes_supported?` | `undefined \| Array<"push" \| "poll" \| "ping">` | Supported CIBA delivery modes: poll, ping, or push. |
| `backchannel_authentication_endpoint?` | `undefined \| string` | HTTPS endpoint for CIBA authentication requests. |
| `backchannel_authentication_request_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted backchannel authentication request signing algorithms. Parsing applies this field's protocol restrictions. |
| `backchannel_user_code_parameter_supported?` | `undefined \| boolean` | Whether CIBA requests support the user_code parameter. |
| `authorization_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted authorization signing algorithms. Parsing applies this field's protocol restrictions. |
| `authorization_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted authorization encryption algorithms. Parsing applies this field's protocol restrictions. |
| `authorization_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted authorization encryption content-encryption methods. |
| `nfv_token_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted nfv token signing algorithms. Parsing applies this field's protocol restrictions. |
| `nfv_token_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted nfv token encryption algorithms. Parsing applies this field's protocol restrictions. |
| `nfv_token_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted nfv token encryption content-encryption methods. |
| `code_challenge_methods_supported?` | `undefined \| Array<string>` | Supported PKCE code challenge methods. |
| `device_authorization_endpoint?` | `undefined \| string` | HTTPS device authorization endpoint, without a fragment. |
| `pushed_authorization_request_endpoint?` | `undefined \| string` | HTTPS Pushed Authorization Request endpoint, without a fragment. |
| `require_pushed_authorization_requests?` | `undefined \| boolean` | Whether clients must use PAR. |
| `require_signed_request_object?` | `undefined \| boolean` | Whether Request Objects must be signed. |
| `dpop_signing_alg_values_supported?` | `undefined \| Array<string>` | Supported asymmetric DPoP signing algorithms; none and symmetric HMAC algorithms are rejected. |
| `authorization_response_iss_parameter_supported?` | `undefined \| boolean` | Whether authorization responses support an issuer identifier parameter. |
| `authorization_details_types_supported?` | `undefined \| Array<string>` | Supported authorization_details type values. |
| `protected_resources?` | `undefined \| Array<string>` | Protected-resource identifiers served by this authorization server. |
| `tls_client_certificate_bound_access_tokens?` | `undefined \| boolean` | Whether this participant supports certificate-bound access tokens. |
| `mtls_endpoint_aliases?` | `undefined \| { [key: string]: unknown; token_endpoint?: undefined \| string; revocation_endpoint?: undefined \| string; introspection_endpoint?: undefined \| string; device_authorization_endpoint?: undefined \| string; pushed_authorization_request_endpoint?: undefined \| string; userinfo_endpoint?: undefined \| string; backchannel_authentication_endpoint?: undefined \| string; }` | Optional HTTPS endpoint aliases for mutual-TLS access. Unknown extension aliases are preserved. |
| `signed_metadata?` | `undefined \| string` | Signed metadata JWT preserved as metadata; parsing does not verify its signature. |
| `service_documentation?` | `undefined \| string` | URL for documentation of this authorization server. |
| `ui_locales_supported?` | `undefined \| Array<string>` | Supported languages for the user interface. |
| `op_policy_uri?` | `undefined \| string` | URL for the provider's privacy policy. |
| `op_tos_uri?` | `undefined \| string` | URL for the provider's terms of service. |
| `organization_name?` | `undefined \| string` | Human-readable organization name. |
| `display_name?` | `undefined \| string` | Human-readable display name. |
| `description?` | `undefined \| string` | Human-readable description. |
| `keywords?` | `undefined \| Array<string>` | Informational search keywords; a supplied list must be nonempty. |
| `contacts?` | `undefined \| Array<string>` | Contact addresses; a supplied list must be nonempty. |
| `logo_uri?` | `undefined \| string` | Logo URL for the entity or Trust Mark described by this metadata. |
| `policy_uri?` | `undefined \| string` | Policy information URL. |
| `information_uri?` | `undefined \| string` | Additional entity information URL. |
| `organization_uri?` | `undefined \| string` | Organization website URL. |
| `organization_identifier?` | `undefined \| string` | Organization identifier supplied as informational metadata. |
| `client_registration_types_supported?` | `undefined \| Array<string>` | Supported registration modes; extension values are permitted. |
| `federation_registration_endpoint?` | `undefined \| string` | Federation-specific registration URL; effective metadata requires an HTTPS, fragment-free value when explicit registration is supported. |

## `OAuthAuthorizationServerPublicationMetadata`

[Source](../../../packages/oidc/src/schemas/metadata.ts#L690)

Partial AS publication metadata. The shared core rules are used by OAuthAuthorizationServerRole.parsePublicationMetadata so omitted requirements can be completed by a Superior; supplied values and applicable relationships are still checked.

<details>
<summary>Type declaration</summary>

```typescript signature
type OAuthAuthorizationServerPublicationMetadata = {
	[key: string]: unknown;
	issuer?: undefined | string;
	authorization_endpoint?: undefined | string;
	token_endpoint?: undefined | string;
	response_types_supported?: undefined | Array<string>;
	response_modes_supported?: undefined | Array<string>;
	grant_types_supported?: undefined | Array<string>;
	scopes_supported?: undefined | Array<string>;
	jwks_uri?: undefined | string;
	signed_jwks_uri?: undefined | string;
	jwks?: undefined | { [key: string]: unknown; keys: Array<JWK>; };
	registration_endpoint?: undefined | string;
	token_endpoint_auth_methods_supported?: undefined | Array<string>;
	client_attestation_signing_alg_values_supported?: undefined | Array<string>;
	client_attestation_pop_signing_alg_values_supported?: undefined | Array<string>;
	challenge_endpoint?: undefined | string;
	token_endpoint_auth_signing_alg_values_supported?: undefined | Array<string>;
	revocation_endpoint?: undefined | string;
	revocation_endpoint_auth_methods_supported?: undefined | Array<string>;
	revocation_endpoint_auth_signing_alg_values_supported?: undefined | Array<string>;
	introspection_endpoint?: undefined | string;
	introspection_endpoint_auth_methods_supported?: undefined | Array<string>;
	introspection_endpoint_auth_signing_alg_values_supported?: undefined | Array<string>;
	introspection_signing_alg_values_supported?: undefined | Array<string>;
	introspection_encryption_alg_values_supported?: undefined | Array<string>;
	introspection_encryption_enc_values_supported?: undefined | Array<string>;
	userinfo_endpoint?: undefined | string;
	acr_values_supported?: undefined | Array<string>;
	subject_types_supported?: undefined | Array<string>;
	id_token_signing_alg_values_supported?: undefined | Array<string>;
	id_token_encryption_alg_values_supported?: undefined | Array<string>;
	id_token_encryption_enc_values_supported?: undefined | Array<string>;
	userinfo_signing_alg_values_supported?: undefined | Array<string>;
	userinfo_encryption_alg_values_supported?: undefined | Array<string>;
	userinfo_encryption_enc_values_supported?: undefined | Array<string>;
	request_object_signing_alg_values_supported?: undefined | Array<string>;
	request_object_encryption_alg_values_supported?: undefined | Array<string>;
	request_object_encryption_enc_values_supported?: undefined | Array<string>;
	display_values_supported?: undefined | Array<string>;
	claim_types_supported?: undefined | Array<string>;
	claims_supported?: undefined | Array<string>;
	claims_locales_supported?: undefined | Array<string>;
	claims_parameter_supported?: undefined | boolean;
	request_parameter_supported?: undefined | boolean;
	request_uri_parameter_supported?: undefined | boolean;
	require_request_uri_registration?: undefined | boolean;
	check_session_iframe?: undefined | string;
	frontchannel_logout_supported?: undefined | boolean;
	frontchannel_logout_session_supported?: undefined | boolean;
	backchannel_logout_supported?: undefined | boolean;
	backchannel_logout_session_supported?: undefined | boolean;
	end_session_endpoint?: undefined | string;
	backchannel_token_delivery_modes_supported?: undefined | Array<"push" | "poll" | "ping">;
	backchannel_authentication_endpoint?: undefined | string;
	backchannel_authentication_request_signing_alg_values_supported?: undefined | Array<string>;
	backchannel_user_code_parameter_supported?: undefined | boolean;
	authorization_signing_alg_values_supported?: undefined | Array<string>;
	authorization_encryption_alg_values_supported?: undefined | Array<string>;
	authorization_encryption_enc_values_supported?: undefined | Array<string>;
	nfv_token_signing_alg_values_supported?: undefined | Array<string>;
	nfv_token_encryption_alg_values_supported?: undefined | Array<string>;
	nfv_token_encryption_enc_values_supported?: undefined | Array<string>;
	code_challenge_methods_supported?: undefined | Array<string>;
	device_authorization_endpoint?: undefined | string;
	pushed_authorization_request_endpoint?: undefined | string;
	require_pushed_authorization_requests?: undefined | boolean;
	require_signed_request_object?: undefined | boolean;
	dpop_signing_alg_values_supported?: undefined | Array<string>;
	authorization_response_iss_parameter_supported?: undefined | boolean;
	authorization_details_types_supported?: undefined | Array<string>;
	protected_resources?: undefined | Array<string>;
	tls_client_certificate_bound_access_tokens?: undefined | boolean;
	mtls_endpoint_aliases?: undefined | { [key: string]: unknown; token_endpoint?: undefined | string; revocation_endpoint?: undefined | string; introspection_endpoint?: undefined | string; device_authorization_endpoint?: undefined | string; pushed_authorization_request_endpoint?: undefined | string; userinfo_endpoint?: undefined | string; backchannel_authentication_endpoint?: undefined | string; };
	signed_metadata?: undefined | string;
	service_documentation?: undefined | string;
	ui_locales_supported?: undefined | Array<string>;
	op_policy_uri?: undefined | string;
	op_tos_uri?: undefined | string;
	organization_name?: undefined | string;
	display_name?: undefined | string;
	description?: undefined | string;
	keywords?: undefined | Array<string>;
	contacts?: undefined | Array<string>;
	logo_uri?: undefined | string;
	policy_uri?: undefined | string;
	information_uri?: undefined | string;
	organization_uri?: undefined | string;
	organization_identifier?: undefined | string;
	client_registration_types_supported?: undefined | Array<string>;
	federation_registration_endpoint?: undefined | string;
};
```

</details>

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `issuer?` | `undefined \| string` | Protocol issuer URL. Federation consumers additionally bind it to the Entity Identifier. |
| `authorization_endpoint?` | `undefined \| string` | HTTPS endpoint for authorization requests; no fragment is allowed. |
| `token_endpoint?` | `undefined \| string` | HTTPS token endpoint; required in effective metadata unless only implicit is supported. |
| `response_types_supported?` | `undefined \| Array<string>` | Supported OAuth response types; required for the normal effective AS profile. |
| `response_modes_supported?` | `undefined \| Array<string>` | Supported authorization response modes. |
| `grant_types_supported?` | `undefined \| Array<string>` | Supported OAuth grant types; omitted values use the protocol's default when evaluating conditional requirements. |
| `scopes_supported?` | `undefined \| Array<string>` | Supported OAuth scopes. |
| `jwks_uri?` | `undefined \| string` | HTTPS URL for public protocol keys, without a fragment. |
| `signed_jwks_uri?` | `undefined \| string` | HTTPS URL for a signed protocol JWK Set, without a fragment. |
| `jwks?` | `undefined \| { [key: string]: unknown; keys: Array<JWK>; }` | JSON Web Key Set. The owning API determines whether these are Federation Entity Keys or protocol keys. |
| `registration_endpoint?` | `undefined \| string` | HTTPS dynamic client registration endpoint. |
| `token_endpoint_auth_methods_supported?` | `undefined \| Array<string>` | Supported authentication methods for token endpoint. |
| `client_attestation_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted client attestation signing algorithms. Parsing applies this field's protocol restrictions. |
| `client_attestation_pop_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted client attestation pop signing algorithms. Parsing applies this field's protocol restrictions. |
| `challenge_endpoint?` | `undefined \| string` | Client-attestation challenge endpoint URL; this schema checks URL syntax, not endpoint trust. |
| `token_endpoint_auth_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted token endpoint auth signing algorithms. Parsing applies this field's protocol restrictions. |
| `revocation_endpoint?` | `undefined \| string` | HTTPS endpoint for token revocation. |
| `revocation_endpoint_auth_methods_supported?` | `undefined \| Array<string>` | Supported authentication methods for revocation endpoint. |
| `revocation_endpoint_auth_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted revocation endpoint auth signing algorithms. Parsing applies this field's protocol restrictions. |
| `introspection_endpoint?` | `undefined \| string` | HTTPS endpoint for token introspection. |
| `introspection_endpoint_auth_methods_supported?` | `undefined \| Array<string>` | Supported authentication methods for introspection endpoint. |
| `introspection_endpoint_auth_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted introspection endpoint auth signing algorithms. Parsing applies this field's protocol restrictions. |
| `introspection_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted introspection signing algorithms. Parsing applies this field's protocol restrictions. |
| `introspection_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted introspection encryption algorithms. Parsing applies this field's protocol restrictions. |
| `introspection_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted introspection encryption content-encryption methods. |
| `userinfo_endpoint?` | `undefined \| string` | HTTPS OpenID Connect UserInfo endpoint. |
| `acr_values_supported?` | `undefined \| Array<string>` | Supported authentication context class reference values. |
| `subject_types_supported?` | `undefined \| Array<string>` | Supported OpenID Connect subject identifier types. |
| `id_token_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted id token signing algorithms. Parsing applies this field's protocol restrictions. |
| `id_token_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted id token encryption algorithms. Parsing applies this field's protocol restrictions. |
| `id_token_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted id token encryption content-encryption methods. |
| `userinfo_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted userinfo signing algorithms. Parsing applies this field's protocol restrictions. |
| `userinfo_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted userinfo encryption algorithms. Parsing applies this field's protocol restrictions. |
| `userinfo_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted userinfo encryption content-encryption methods. |
| `request_object_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted request object signing algorithms. Parsing applies this field's protocol restrictions. |
| `request_object_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted request object encryption algorithms. Parsing applies this field's protocol restrictions. |
| `request_object_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted request object encryption content-encryption methods. |
| `display_values_supported?` | `undefined \| Array<string>` | Supported OpenID Connect display modes. |
| `claim_types_supported?` | `undefined \| Array<string>` | Supported OpenID Connect claim representations. |
| `claims_supported?` | `undefined \| Array<string>` | Supported claim names. |
| `claims_locales_supported?` | `undefined \| Array<string>` | Supported languages for returned claims. |
| `claims_parameter_supported?` | `undefined \| boolean` | Whether the OpenID Connect claims request parameter is supported. |
| `request_parameter_supported?` | `undefined \| boolean` | Whether a Request Object can be sent using the request parameter. |
| `request_uri_parameter_supported?` | `undefined \| boolean` | Whether Request Objects can be referenced using request_uri. |
| `require_request_uri_registration?` | `undefined \| boolean` | Whether Request Object URIs must be registered in advance. |
| `check_session_iframe?` | `undefined \| string` | HTTPS session-management iframe URL. |
| `frontchannel_logout_supported?` | `undefined \| boolean` | Whether front-channel logout is supported. |
| `frontchannel_logout_session_supported?` | `undefined \| boolean` | Whether front-channel logout supports session identifiers. |
| `backchannel_logout_supported?` | `undefined \| boolean` | Whether back-channel logout is supported. |
| `backchannel_logout_session_supported?` | `undefined \| boolean` | Whether back-channel logout supports session identifiers. |
| `end_session_endpoint?` | `undefined \| string` | HTTPS endpoint for initiating logout. |
| `backchannel_token_delivery_modes_supported?` | `undefined \| Array<"push" \| "poll" \| "ping">` | Supported CIBA delivery modes: poll, ping, or push. |
| `backchannel_authentication_endpoint?` | `undefined \| string` | HTTPS endpoint for CIBA authentication requests. |
| `backchannel_authentication_request_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted backchannel authentication request signing algorithms. Parsing applies this field's protocol restrictions. |
| `backchannel_user_code_parameter_supported?` | `undefined \| boolean` | Whether CIBA requests support the user_code parameter. |
| `authorization_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted authorization signing algorithms. Parsing applies this field's protocol restrictions. |
| `authorization_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted authorization encryption algorithms. Parsing applies this field's protocol restrictions. |
| `authorization_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted authorization encryption content-encryption methods. |
| `nfv_token_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted nfv token signing algorithms. Parsing applies this field's protocol restrictions. |
| `nfv_token_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted nfv token encryption algorithms. Parsing applies this field's protocol restrictions. |
| `nfv_token_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted nfv token encryption content-encryption methods. |
| `code_challenge_methods_supported?` | `undefined \| Array<string>` | Supported PKCE code challenge methods. |
| `device_authorization_endpoint?` | `undefined \| string` | HTTPS device authorization endpoint, without a fragment. |
| `pushed_authorization_request_endpoint?` | `undefined \| string` | HTTPS Pushed Authorization Request endpoint, without a fragment. |
| `require_pushed_authorization_requests?` | `undefined \| boolean` | Whether clients must use PAR. |
| `require_signed_request_object?` | `undefined \| boolean` | Whether Request Objects must be signed. |
| `dpop_signing_alg_values_supported?` | `undefined \| Array<string>` | Supported asymmetric DPoP signing algorithms; none and symmetric HMAC algorithms are rejected. |
| `authorization_response_iss_parameter_supported?` | `undefined \| boolean` | Whether authorization responses support an issuer identifier parameter. |
| `authorization_details_types_supported?` | `undefined \| Array<string>` | Supported authorization_details type values. |
| `protected_resources?` | `undefined \| Array<string>` | Protected-resource identifiers served by this authorization server. |
| `tls_client_certificate_bound_access_tokens?` | `undefined \| boolean` | Whether this participant supports certificate-bound access tokens. |
| `mtls_endpoint_aliases?` | `undefined \| { [key: string]: unknown; token_endpoint?: undefined \| string; revocation_endpoint?: undefined \| string; introspection_endpoint?: undefined \| string; device_authorization_endpoint?: undefined \| string; pushed_authorization_request_endpoint?: undefined \| string; userinfo_endpoint?: undefined \| string; backchannel_authentication_endpoint?: undefined \| string; }` | Optional HTTPS endpoint aliases for mutual-TLS access. Unknown extension aliases are preserved. |
| `signed_metadata?` | `undefined \| string` | Signed metadata JWT preserved as metadata; parsing does not verify its signature. |
| `service_documentation?` | `undefined \| string` | URL for documentation of this authorization server. |
| `ui_locales_supported?` | `undefined \| Array<string>` | Supported languages for the user interface. |
| `op_policy_uri?` | `undefined \| string` | URL for the provider's privacy policy. |
| `op_tos_uri?` | `undefined \| string` | URL for the provider's terms of service. |
| `organization_name?` | `undefined \| string` | Human-readable organization name. |
| `display_name?` | `undefined \| string` | Human-readable display name. |
| `description?` | `undefined \| string` | Human-readable description. |
| `keywords?` | `undefined \| Array<string>` | Informational search keywords; a supplied list must be nonempty. |
| `contacts?` | `undefined \| Array<string>` | Contact addresses; a supplied list must be nonempty. |
| `logo_uri?` | `undefined \| string` | Logo URL for the entity or Trust Mark described by this metadata. |
| `policy_uri?` | `undefined \| string` | Policy information URL. |
| `information_uri?` | `undefined \| string` | Additional entity information URL. |
| `organization_uri?` | `undefined \| string` | Organization website URL. |
| `organization_identifier?` | `undefined \| string` | Organization identifier supplied as informational metadata. |
| `client_registration_types_supported?` | `undefined \| Array<string>` | Supported registration modes; extension values are permitted. |
| `federation_registration_endpoint?` | `undefined \| string` | Federation-specific registration URL; effective metadata requires an HTTPS, fragment-free value when explicit registration is supported. |

## `OAuthClientMetadata`

[Source](../../../packages/oidc/src/schemas/metadata.ts#L611)

Effective OAuth client metadata type. Required relationships, including redirect-based flows, are enforced at runtime even where fields remain optional in TypeScript. Use the matching role's parseMetadata method. Registration-response credentials are rejected in publication metadata; unknown extensions are preserved.

<details>
<summary>Type declaration</summary>

```typescript signature
type OAuthClientMetadata = {
	[key: string]: unknown;
	jwks_uri?: undefined | string;
	jwks?: undefined | { [key: string]: unknown; keys: Array<JWK>; };
	software_id?: undefined | string;
	software_version?: undefined | string;
	client_registration_types?: undefined | Array<string>;
	signed_jwks_uri?: undefined | string;
	organization_identifier?: undefined | string;
	organization_name?: undefined | string;
	display_name?: undefined | string;
	description?: undefined | string;
	keywords?: undefined | Array<string>;
	contacts?: undefined | Array<string>;
	logo_uri?: undefined | string;
	policy_uri?: undefined | string;
	information_uri?: undefined | string;
	organization_uri?: undefined | string;
	redirect_uris?: undefined | Array<string>;
	token_endpoint_auth_method?: undefined | string;
	token_endpoint_auth_signing_alg?: undefined | string;
	grant_types?: undefined | Array<string>;
	response_types?: undefined | Array<string>;
	client_name?: undefined | string;
	client_uri?: undefined | string;
	scope?: undefined | string;
	tos_uri?: undefined | string;
	sector_identifier_uri?: undefined | string;
	request_uris?: undefined | Array<string>;
	subject_type?: undefined | "public" | "pairwise";
	id_token_signed_response_alg?: undefined | string;
	id_token_encrypted_response_alg?: undefined | string;
	id_token_encrypted_response_enc?: undefined | string;
	userinfo_signed_response_alg?: undefined | string;
	userinfo_encrypted_response_alg?: undefined | string;
	userinfo_encrypted_response_enc?: undefined | string;
	request_object_signing_alg?: undefined | string;
	request_object_encryption_alg?: undefined | string;
	request_object_encryption_enc?: undefined | string;
	default_max_age?: undefined | number;
	require_auth_time?: undefined | boolean;
	default_acr_values?: undefined | Array<string>;
	initiate_login_uri?: undefined | string;
	post_logout_redirect_uris?: undefined | Array<string>;
	backchannel_token_delivery_mode?: undefined | "push" | "poll" | "ping";
	backchannel_client_notification_endpoint?: undefined | string;
	backchannel_authentication_request_signing_alg?: undefined | string;
	backchannel_user_code_parameter?: undefined | boolean;
	frontchannel_logout_uri?: undefined | string;
	frontchannel_logout_session_required?: undefined | boolean;
	backchannel_logout_uri?: undefined | string;
	backchannel_logout_session_required?: undefined | boolean;
	application_type?: undefined | "web" | "native";
	subject_types_supported?: undefined | Array<string>;
	id_token_signing_alg_values_supported?: undefined | Array<string>;
	id_token_encryption_alg_values_supported?: undefined | Array<string>;
	id_token_encryption_enc_values_supported?: undefined | Array<string>;
	userinfo_signing_alg_values_supported?: undefined | Array<string>;
	userinfo_encryption_alg_values_supported?: undefined | Array<string>;
	userinfo_encryption_enc_values_supported?: undefined | Array<string>;
	request_object_signing_alg_values_supported?: undefined | Array<string>;
	request_object_encryption_alg_values_supported?: undefined | Array<string>;
	request_object_encryption_enc_values_supported?: undefined | Array<string>;
	token_endpoint_auth_methods_supported?: undefined | Array<string>;
	token_endpoint_auth_signing_alg_values_supported?: undefined | Array<string>;
	backchannel_authentication_request_signing_alg_values_supported?: undefined | Array<string>;
	authorization_signing_alg_values_supported?: undefined | Array<string>;
	authorization_encryption_alg_values_supported?: undefined | Array<string>;
	authorization_encryption_enc_values_supported?: undefined | Array<string>;
	introspection_signing_alg_values_supported?: undefined | Array<string>;
	introspection_encryption_alg_values_supported?: undefined | Array<string>;
	introspection_encryption_enc_values_supported?: undefined | Array<string>;
	software_statement?: undefined | string;
	claims_redirect_uris?: undefined | Array<string>;
	nfv_token_signed_response_alg?: undefined | string;
	nfv_token_encrypted_response_alg?: undefined | string;
	nfv_token_encrypted_response_enc?: undefined | string;
	tls_client_certificate_bound_access_tokens?: undefined | boolean;
	tls_client_auth_subject_dn?: undefined | string;
	tls_client_auth_san_dns?: undefined | string;
	tls_client_auth_san_uri?: undefined | string;
	tls_client_auth_san_ip?: undefined | string;
	tls_client_auth_san_email?: undefined | string;
	require_signed_request_object?: undefined | boolean;
	require_pushed_authorization_requests?: undefined | boolean;
	use_mtls_endpoint_aliases?: undefined | boolean;
	authorization_details_types?: undefined | Array<string>;
	dpop_bound_access_tokens?: undefined | boolean;
	introspection_signed_response_alg?: undefined | string;
	introspection_encrypted_response_alg?: undefined | string;
	introspection_encrypted_response_enc?: undefined | string;
	authorization_signed_response_alg?: undefined | string;
	authorization_encrypted_response_alg?: undefined | string;
	authorization_encrypted_response_enc?: undefined | string;
};
```

</details>

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `jwks_uri?` | `undefined \| string` | HTTPS URL for public protocol keys, without a fragment. |
| `jwks?` | `undefined \| { [key: string]: unknown; keys: Array<JWK>; }` | JSON Web Key Set. The owning API determines whether these are Federation Entity Keys or protocol keys. |
| `software_id?` | `undefined \| string` | Client software identifier. |
| `software_version?` | `undefined \| string` | Client software version. |
| `client_registration_types?` | `undefined \| Array<string>` | Supported client registration modes. Additional string values remain permitted. |
| `signed_jwks_uri?` | `undefined \| string` | HTTPS URL for a signed protocol JWK Set, without a fragment. |
| `organization_identifier?` | `undefined \| string` | Organization identifier supplied as informational metadata. |
| `organization_name?` | `undefined \| string` | Human-readable organization name. |
| `display_name?` | `undefined \| string` | Human-readable display name. |
| `description?` | `undefined \| string` | Human-readable description. |
| `keywords?` | `undefined \| Array<string>` | Informational search keywords; a supplied list must be nonempty. |
| `contacts?` | `undefined \| Array<string>` | Contact addresses; a supplied list must be nonempty. |
| `logo_uri?` | `undefined \| string` | Logo URL for the entity or Trust Mark described by this metadata. |
| `policy_uri?` | `undefined \| string` | Policy information URL. |
| `information_uri?` | `undefined \| string` | Additional entity information URL. |
| `organization_uri?` | `undefined \| string` | Organization website URL. |
| `redirect_uris?` | `undefined \| Array<string>` | Registered redirect URLs. The effective parser enforces flow-dependent presence and redirect security rules. |
| `token_endpoint_auth_method?` | `undefined \| string` | Selected token endpoint authentication method; extension string values are preserved. |
| `token_endpoint_auth_signing_alg?` | `undefined \| string` | Signing algorithm for JWT client authentication; none is rejected. |
| `grant_types?` | `undefined \| Array<string>` | Client grant types; conditional redirect, response-type, and CIBA requirements are checked by the parser. |
| `response_types?` | `undefined \| Array<string>` | Client response types; effective metadata checks consistency with the grant types. |
| `client_name?` | `undefined \| string` | Human-readable client name. |
| `client_uri?` | `undefined \| string` | Client information URL. |
| `scope?` | `undefined \| string` | Space-separated OAuth scopes requested or registered for this client. |
| `tos_uri?` | `undefined \| string` | Client terms-of-service URL. |
| `sector_identifier_uri?` | `undefined \| string` | HTTPS URL for the client's sector identifier document. Parsing does not fetch the document. |
| `request_uris?` | `undefined \| Array<string>` | Registered Request Object URLs. |
| `subject_type?` | `undefined \| "public" \| "pairwise"` | Selected OIDC subject identifier type: public or pairwise; it must belong to any supplied subject_types_supported choices. |
| `id_token_signed_response_alg?` | `undefined \| string` | Selected signing algorithm for id token responses. |
| `id_token_encrypted_response_alg?` | `undefined \| string` | Selected key-management algorithm for id token response encryption. |
| `id_token_encrypted_response_enc?` | `undefined \| string` | Selected content-encryption method for id token responses. |
| `userinfo_signed_response_alg?` | `undefined \| string` | Selected signing algorithm for userinfo responses. |
| `userinfo_encrypted_response_alg?` | `undefined \| string` | Selected key-management algorithm for userinfo response encryption. |
| `userinfo_encrypted_response_enc?` | `undefined \| string` | Selected content-encryption method for userinfo responses. |
| `request_object_signing_alg?` | `undefined \| string` | Selected Request Object signing algorithm. |
| `request_object_encryption_alg?` | `undefined \| string` | Selected Request Object key-management algorithm. |
| `request_object_encryption_enc?` | `undefined \| string` | Selected Request Object content-encryption method. |
| `default_max_age?` | `undefined \| number` | Default authentication age in nonnegative integer seconds. |
| `require_auth_time?` | `undefined \| boolean` | Whether an authentication time claim is required by the client. |
| `default_acr_values?` | `undefined \| Array<string>` | Default requested authentication context class reference values. |
| `initiate_login_uri?` | `undefined \| string` | HTTPS URL at which the client accepts third-party initiated login. |
| `post_logout_redirect_uris?` | `undefined \| Array<string>` | Registered post-logout redirect URLs. |
| `backchannel_token_delivery_mode?` | `undefined \| "push" \| "poll" \| "ping"` | Selected CIBA mode: poll, ping, or push. Effective metadata enforces its grant and notification dependencies. |
| `backchannel_client_notification_endpoint?` | `undefined \| string` | HTTPS client notification endpoint, required for effective CIBA ping or push delivery. |
| `backchannel_authentication_request_signing_alg?` | `undefined \| string` | Signing algorithm for CIBA authentication requests. |
| `backchannel_user_code_parameter?` | `undefined \| boolean` | Whether the CIBA client uses the user_code parameter. |
| `frontchannel_logout_uri?` | `undefined \| string` | HTTPS front-channel logout URI, without a fragment. |
| `frontchannel_logout_session_required?` | `undefined \| boolean` | Whether the client requires session information for front-channel logout. |
| `backchannel_logout_uri?` | `undefined \| string` | HTTPS back-channel logout URI, without a fragment. |
| `backchannel_logout_session_required?` | `undefined \| boolean` | Whether the client requires session information for back-channel logout. |
| `application_type?` | `undefined \| "web" \| "native"` | OIDC application type: web or native. Redirect requirements depend on this value and the flow. |
| `subject_types_supported?` | `undefined \| Array<string>` | Supported OpenID Connect subject identifier types. |
| `id_token_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted id token signing algorithms. Parsing applies this field's protocol restrictions. |
| `id_token_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted id token encryption algorithms. Parsing applies this field's protocol restrictions. |
| `id_token_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted id token encryption content-encryption methods. |
| `userinfo_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted userinfo signing algorithms. Parsing applies this field's protocol restrictions. |
| `userinfo_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted userinfo encryption algorithms. Parsing applies this field's protocol restrictions. |
| `userinfo_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted userinfo encryption content-encryption methods. |
| `request_object_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted request object signing algorithms. Parsing applies this field's protocol restrictions. |
| `request_object_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted request object encryption algorithms. Parsing applies this field's protocol restrictions. |
| `request_object_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted request object encryption content-encryption methods. |
| `token_endpoint_auth_methods_supported?` | `undefined \| Array<string>` | Supported authentication methods for token endpoint. |
| `token_endpoint_auth_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted token endpoint auth signing algorithms. Parsing applies this field's protocol restrictions. |
| `backchannel_authentication_request_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted backchannel authentication request signing algorithms. Parsing applies this field's protocol restrictions. |
| `authorization_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted authorization signing algorithms. Parsing applies this field's protocol restrictions. |
| `authorization_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted authorization encryption algorithms. Parsing applies this field's protocol restrictions. |
| `authorization_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted authorization encryption content-encryption methods. |
| `introspection_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted introspection signing algorithms. Parsing applies this field's protocol restrictions. |
| `introspection_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted introspection encryption algorithms. Parsing applies this field's protocol restrictions. |
| `introspection_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted introspection encryption content-encryption methods. |
| `software_statement?` | `undefined \| string` | Software statement JWT preserved as metadata; parsing does not authenticate its signer. |
| `claims_redirect_uris?` | `undefined \| Array<string>` | Client URLs used for claims-redirection workflows. |
| `nfv_token_signed_response_alg?` | `undefined \| string` | Selected signing algorithm for nfv token responses. |
| `nfv_token_encrypted_response_alg?` | `undefined \| string` | Selected key-management algorithm for nfv token response encryption. |
| `nfv_token_encrypted_response_enc?` | `undefined \| string` | Selected content-encryption method for nfv token responses. |
| `tls_client_certificate_bound_access_tokens?` | `undefined \| boolean` | Whether this participant supports certificate-bound access tokens. |
| `tls_client_auth_subject_dn?` | `undefined \| string` | Expected certificate subject distinguished name. Effective tls_client_auth metadata requires exactly one certificate selector. |
| `tls_client_auth_san_dns?` | `undefined \| string` | Expected DNS subjectAltName. Effective tls_client_auth metadata requires exactly one certificate selector. |
| `tls_client_auth_san_uri?` | `undefined \| string` | Expected URI subjectAltName. Effective tls_client_auth metadata requires exactly one certificate selector. |
| `tls_client_auth_san_ip?` | `undefined \| string` | Expected IP subjectAltName. Effective tls_client_auth metadata requires exactly one certificate selector. |
| `tls_client_auth_san_email?` | `undefined \| string` | Expected email subjectAltName. Effective tls_client_auth metadata requires exactly one certificate selector. |
| `require_signed_request_object?` | `undefined \| boolean` | Whether Request Objects must be signed. |
| `require_pushed_authorization_requests?` | `undefined \| boolean` | Whether clients must use PAR. |
| `use_mtls_endpoint_aliases?` | `undefined \| boolean` | Whether the client requests the server's mutual-TLS endpoint aliases. |
| `authorization_details_types?` | `undefined \| Array<string>` | Authorization-details types requested by the client. |
| `dpop_bound_access_tokens?` | `undefined \| boolean` | Whether the client requests DPoP-bound access tokens. |
| `introspection_signed_response_alg?` | `undefined \| string` | Selected signing algorithm for introspection responses. |
| `introspection_encrypted_response_alg?` | `undefined \| string` | Selected key-management algorithm for introspection response encryption. |
| `introspection_encrypted_response_enc?` | `undefined \| string` | Selected content-encryption method for introspection responses. |
| `authorization_signed_response_alg?` | `undefined \| string` | Selected signing algorithm for authorization responses. |
| `authorization_encrypted_response_alg?` | `undefined \| string` | Selected key-management algorithm for authorization response encryption. |
| `authorization_encrypted_response_enc?` | `undefined \| string` | Selected content-encryption method for authorization responses. |

## `OAuthClientPublicationMetadata`

[Source](../../../packages/oidc/src/schemas/metadata.ts#L693)

Publication metadata type for a client EC or Superior statement whose missing fields may be completed later. The matching role's parsePublicationMetadata checks supplied fields and applicable consistency rules, while deferring effective requirements. Registration-response credential fields cannot be published.

<details>
<summary>Type declaration</summary>

```typescript signature
type OAuthClientPublicationMetadata = {
	[key: string]: unknown;
	jwks_uri?: undefined | string;
	jwks?: undefined | { [key: string]: unknown; keys: Array<JWK>; };
	software_id?: undefined | string;
	software_version?: undefined | string;
	client_registration_types?: undefined | Array<string>;
	signed_jwks_uri?: undefined | string;
	organization_identifier?: undefined | string;
	organization_name?: undefined | string;
	display_name?: undefined | string;
	description?: undefined | string;
	keywords?: undefined | Array<string>;
	contacts?: undefined | Array<string>;
	logo_uri?: undefined | string;
	policy_uri?: undefined | string;
	information_uri?: undefined | string;
	organization_uri?: undefined | string;
	redirect_uris?: undefined | Array<string>;
	token_endpoint_auth_method?: undefined | string;
	token_endpoint_auth_signing_alg?: undefined | string;
	grant_types?: undefined | Array<string>;
	response_types?: undefined | Array<string>;
	client_name?: undefined | string;
	client_uri?: undefined | string;
	scope?: undefined | string;
	tos_uri?: undefined | string;
	sector_identifier_uri?: undefined | string;
	request_uris?: undefined | Array<string>;
	subject_type?: undefined | "public" | "pairwise";
	id_token_signed_response_alg?: undefined | string;
	id_token_encrypted_response_alg?: undefined | string;
	id_token_encrypted_response_enc?: undefined | string;
	userinfo_signed_response_alg?: undefined | string;
	userinfo_encrypted_response_alg?: undefined | string;
	userinfo_encrypted_response_enc?: undefined | string;
	request_object_signing_alg?: undefined | string;
	request_object_encryption_alg?: undefined | string;
	request_object_encryption_enc?: undefined | string;
	default_max_age?: undefined | number;
	require_auth_time?: undefined | boolean;
	default_acr_values?: undefined | Array<string>;
	initiate_login_uri?: undefined | string;
	post_logout_redirect_uris?: undefined | Array<string>;
	backchannel_token_delivery_mode?: undefined | "push" | "poll" | "ping";
	backchannel_client_notification_endpoint?: undefined | string;
	backchannel_authentication_request_signing_alg?: undefined | string;
	backchannel_user_code_parameter?: undefined | boolean;
	frontchannel_logout_uri?: undefined | string;
	frontchannel_logout_session_required?: undefined | boolean;
	backchannel_logout_uri?: undefined | string;
	backchannel_logout_session_required?: undefined | boolean;
	application_type?: undefined | "web" | "native";
	subject_types_supported?: undefined | Array<string>;
	id_token_signing_alg_values_supported?: undefined | Array<string>;
	id_token_encryption_alg_values_supported?: undefined | Array<string>;
	id_token_encryption_enc_values_supported?: undefined | Array<string>;
	userinfo_signing_alg_values_supported?: undefined | Array<string>;
	userinfo_encryption_alg_values_supported?: undefined | Array<string>;
	userinfo_encryption_enc_values_supported?: undefined | Array<string>;
	request_object_signing_alg_values_supported?: undefined | Array<string>;
	request_object_encryption_alg_values_supported?: undefined | Array<string>;
	request_object_encryption_enc_values_supported?: undefined | Array<string>;
	token_endpoint_auth_methods_supported?: undefined | Array<string>;
	token_endpoint_auth_signing_alg_values_supported?: undefined | Array<string>;
	backchannel_authentication_request_signing_alg_values_supported?: undefined | Array<string>;
	authorization_signing_alg_values_supported?: undefined | Array<string>;
	authorization_encryption_alg_values_supported?: undefined | Array<string>;
	authorization_encryption_enc_values_supported?: undefined | Array<string>;
	introspection_signing_alg_values_supported?: undefined | Array<string>;
	introspection_encryption_alg_values_supported?: undefined | Array<string>;
	introspection_encryption_enc_values_supported?: undefined | Array<string>;
	software_statement?: undefined | string;
	claims_redirect_uris?: undefined | Array<string>;
	nfv_token_signed_response_alg?: undefined | string;
	nfv_token_encrypted_response_alg?: undefined | string;
	nfv_token_encrypted_response_enc?: undefined | string;
	tls_client_certificate_bound_access_tokens?: undefined | boolean;
	tls_client_auth_subject_dn?: undefined | string;
	tls_client_auth_san_dns?: undefined | string;
	tls_client_auth_san_uri?: undefined | string;
	tls_client_auth_san_ip?: undefined | string;
	tls_client_auth_san_email?: undefined | string;
	require_signed_request_object?: undefined | boolean;
	require_pushed_authorization_requests?: undefined | boolean;
	use_mtls_endpoint_aliases?: undefined | boolean;
	authorization_details_types?: undefined | Array<string>;
	dpop_bound_access_tokens?: undefined | boolean;
	introspection_signed_response_alg?: undefined | string;
	introspection_encrypted_response_alg?: undefined | string;
	introspection_encrypted_response_enc?: undefined | string;
	authorization_signed_response_alg?: undefined | string;
	authorization_encrypted_response_alg?: undefined | string;
	authorization_encrypted_response_enc?: undefined | string;
};
```

</details>

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `jwks_uri?` | `undefined \| string` | HTTPS URL for public protocol keys, without a fragment. |
| `jwks?` | `undefined \| { [key: string]: unknown; keys: Array<JWK>; }` | JSON Web Key Set. The owning API determines whether these are Federation Entity Keys or protocol keys. |
| `software_id?` | `undefined \| string` | Client software identifier. |
| `software_version?` | `undefined \| string` | Client software version. |
| `client_registration_types?` | `undefined \| Array<string>` | Supported client registration modes. Additional string values remain permitted. |
| `signed_jwks_uri?` | `undefined \| string` | HTTPS URL for a signed protocol JWK Set, without a fragment. |
| `organization_identifier?` | `undefined \| string` | Organization identifier supplied as informational metadata. |
| `organization_name?` | `undefined \| string` | Human-readable organization name. |
| `display_name?` | `undefined \| string` | Human-readable display name. |
| `description?` | `undefined \| string` | Human-readable description. |
| `keywords?` | `undefined \| Array<string>` | Informational search keywords; a supplied list must be nonempty. |
| `contacts?` | `undefined \| Array<string>` | Contact addresses; a supplied list must be nonempty. |
| `logo_uri?` | `undefined \| string` | Logo URL for the entity or Trust Mark described by this metadata. |
| `policy_uri?` | `undefined \| string` | Policy information URL. |
| `information_uri?` | `undefined \| string` | Additional entity information URL. |
| `organization_uri?` | `undefined \| string` | Organization website URL. |
| `redirect_uris?` | `undefined \| Array<string>` | Registered redirect URLs. The effective parser enforces flow-dependent presence and redirect security rules. |
| `token_endpoint_auth_method?` | `undefined \| string` | Selected token endpoint authentication method; extension string values are preserved. |
| `token_endpoint_auth_signing_alg?` | `undefined \| string` | Signing algorithm for JWT client authentication; none is rejected. |
| `grant_types?` | `undefined \| Array<string>` | Client grant types; conditional redirect, response-type, and CIBA requirements are checked by the parser. |
| `response_types?` | `undefined \| Array<string>` | Client response types; effective metadata checks consistency with the grant types. |
| `client_name?` | `undefined \| string` | Human-readable client name. |
| `client_uri?` | `undefined \| string` | Client information URL. |
| `scope?` | `undefined \| string` | Space-separated OAuth scopes requested or registered for this client. |
| `tos_uri?` | `undefined \| string` | Client terms-of-service URL. |
| `sector_identifier_uri?` | `undefined \| string` | HTTPS URL for the client's sector identifier document. Parsing does not fetch the document. |
| `request_uris?` | `undefined \| Array<string>` | Registered Request Object URLs. |
| `subject_type?` | `undefined \| "public" \| "pairwise"` | Selected OIDC subject identifier type: public or pairwise; it must belong to any supplied subject_types_supported choices. |
| `id_token_signed_response_alg?` | `undefined \| string` | Selected signing algorithm for id token responses. |
| `id_token_encrypted_response_alg?` | `undefined \| string` | Selected key-management algorithm for id token response encryption. |
| `id_token_encrypted_response_enc?` | `undefined \| string` | Selected content-encryption method for id token responses. |
| `userinfo_signed_response_alg?` | `undefined \| string` | Selected signing algorithm for userinfo responses. |
| `userinfo_encrypted_response_alg?` | `undefined \| string` | Selected key-management algorithm for userinfo response encryption. |
| `userinfo_encrypted_response_enc?` | `undefined \| string` | Selected content-encryption method for userinfo responses. |
| `request_object_signing_alg?` | `undefined \| string` | Selected Request Object signing algorithm. |
| `request_object_encryption_alg?` | `undefined \| string` | Selected Request Object key-management algorithm. |
| `request_object_encryption_enc?` | `undefined \| string` | Selected Request Object content-encryption method. |
| `default_max_age?` | `undefined \| number` | Default authentication age in nonnegative integer seconds. |
| `require_auth_time?` | `undefined \| boolean` | Whether an authentication time claim is required by the client. |
| `default_acr_values?` | `undefined \| Array<string>` | Default requested authentication context class reference values. |
| `initiate_login_uri?` | `undefined \| string` | HTTPS URL at which the client accepts third-party initiated login. |
| `post_logout_redirect_uris?` | `undefined \| Array<string>` | Registered post-logout redirect URLs. |
| `backchannel_token_delivery_mode?` | `undefined \| "push" \| "poll" \| "ping"` | Selected CIBA mode: poll, ping, or push. Effective metadata enforces its grant and notification dependencies. |
| `backchannel_client_notification_endpoint?` | `undefined \| string` | HTTPS client notification endpoint, required for effective CIBA ping or push delivery. |
| `backchannel_authentication_request_signing_alg?` | `undefined \| string` | Signing algorithm for CIBA authentication requests. |
| `backchannel_user_code_parameter?` | `undefined \| boolean` | Whether the CIBA client uses the user_code parameter. |
| `frontchannel_logout_uri?` | `undefined \| string` | HTTPS front-channel logout URI, without a fragment. |
| `frontchannel_logout_session_required?` | `undefined \| boolean` | Whether the client requires session information for front-channel logout. |
| `backchannel_logout_uri?` | `undefined \| string` | HTTPS back-channel logout URI, without a fragment. |
| `backchannel_logout_session_required?` | `undefined \| boolean` | Whether the client requires session information for back-channel logout. |
| `application_type?` | `undefined \| "web" \| "native"` | OIDC application type: web or native. Redirect requirements depend on this value and the flow. |
| `subject_types_supported?` | `undefined \| Array<string>` | Supported OpenID Connect subject identifier types. |
| `id_token_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted id token signing algorithms. Parsing applies this field's protocol restrictions. |
| `id_token_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted id token encryption algorithms. Parsing applies this field's protocol restrictions. |
| `id_token_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted id token encryption content-encryption methods. |
| `userinfo_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted userinfo signing algorithms. Parsing applies this field's protocol restrictions. |
| `userinfo_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted userinfo encryption algorithms. Parsing applies this field's protocol restrictions. |
| `userinfo_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted userinfo encryption content-encryption methods. |
| `request_object_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted request object signing algorithms. Parsing applies this field's protocol restrictions. |
| `request_object_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted request object encryption algorithms. Parsing applies this field's protocol restrictions. |
| `request_object_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted request object encryption content-encryption methods. |
| `token_endpoint_auth_methods_supported?` | `undefined \| Array<string>` | Supported authentication methods for token endpoint. |
| `token_endpoint_auth_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted token endpoint auth signing algorithms. Parsing applies this field's protocol restrictions. |
| `backchannel_authentication_request_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted backchannel authentication request signing algorithms. Parsing applies this field's protocol restrictions. |
| `authorization_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted authorization signing algorithms. Parsing applies this field's protocol restrictions. |
| `authorization_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted authorization encryption algorithms. Parsing applies this field's protocol restrictions. |
| `authorization_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted authorization encryption content-encryption methods. |
| `introspection_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted introspection signing algorithms. Parsing applies this field's protocol restrictions. |
| `introspection_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted introspection encryption algorithms. Parsing applies this field's protocol restrictions. |
| `introspection_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted introspection encryption content-encryption methods. |
| `software_statement?` | `undefined \| string` | Software statement JWT preserved as metadata; parsing does not authenticate its signer. |
| `claims_redirect_uris?` | `undefined \| Array<string>` | Client URLs used for claims-redirection workflows. |
| `nfv_token_signed_response_alg?` | `undefined \| string` | Selected signing algorithm for nfv token responses. |
| `nfv_token_encrypted_response_alg?` | `undefined \| string` | Selected key-management algorithm for nfv token response encryption. |
| `nfv_token_encrypted_response_enc?` | `undefined \| string` | Selected content-encryption method for nfv token responses. |
| `tls_client_certificate_bound_access_tokens?` | `undefined \| boolean` | Whether this participant supports certificate-bound access tokens. |
| `tls_client_auth_subject_dn?` | `undefined \| string` | Expected certificate subject distinguished name. Effective tls_client_auth metadata requires exactly one certificate selector. |
| `tls_client_auth_san_dns?` | `undefined \| string` | Expected DNS subjectAltName. Effective tls_client_auth metadata requires exactly one certificate selector. |
| `tls_client_auth_san_uri?` | `undefined \| string` | Expected URI subjectAltName. Effective tls_client_auth metadata requires exactly one certificate selector. |
| `tls_client_auth_san_ip?` | `undefined \| string` | Expected IP subjectAltName. Effective tls_client_auth metadata requires exactly one certificate selector. |
| `tls_client_auth_san_email?` | `undefined \| string` | Expected email subjectAltName. Effective tls_client_auth metadata requires exactly one certificate selector. |
| `require_signed_request_object?` | `undefined \| boolean` | Whether Request Objects must be signed. |
| `require_pushed_authorization_requests?` | `undefined \| boolean` | Whether clients must use PAR. |
| `use_mtls_endpoint_aliases?` | `undefined \| boolean` | Whether the client requests the server's mutual-TLS endpoint aliases. |
| `authorization_details_types?` | `undefined \| Array<string>` | Authorization-details types requested by the client. |
| `dpop_bound_access_tokens?` | `undefined \| boolean` | Whether the client requests DPoP-bound access tokens. |
| `introspection_signed_response_alg?` | `undefined \| string` | Selected signing algorithm for introspection responses. |
| `introspection_encrypted_response_alg?` | `undefined \| string` | Selected key-management algorithm for introspection response encryption. |
| `introspection_encrypted_response_enc?` | `undefined \| string` | Selected content-encryption method for introspection responses. |
| `authorization_signed_response_alg?` | `undefined \| string` | Selected signing algorithm for authorization responses. |
| `authorization_encrypted_response_alg?` | `undefined \| string` | Selected key-management algorithm for authorization response encryption. |
| `authorization_encrypted_response_enc?` | `undefined \| string` | Selected content-encryption method for authorization responses. |

## `OAuthClientRegistrationResponseMetadata`

[Source](../../../packages/oidc/src/schemas/metadata.ts#L607)

Client metadata carried in a verified Explicit Registration response. client_id is required; optional secrets and management credentials belong in this block. The OIDC response rejects plural RP Metadata Choices inputs after the protocol engine selects singular values. Shape validity alone does not authenticate a response or enforce read-only token permissions.

<details>
<summary>Type declaration</summary>

```typescript signature
type OAuthClientRegistrationResponseMetadata = {
	[key: string]: unknown;
	client_id: string;
	client_secret?: undefined | string;
	client_id_issued_at?: undefined | number;
	client_secret_expires_at?: undefined | number;
	registration_access_token?: undefined | string;
	registration_client_uri?: undefined | string;
	jwks_uri?: undefined | string;
	jwks?: undefined | { [key: string]: unknown; keys: Array<JWK>; };
	software_id?: undefined | string;
	software_version?: undefined | string;
	client_registration_types?: undefined | Array<string>;
	signed_jwks_uri?: undefined | string;
	organization_identifier?: undefined | string;
	organization_name?: undefined | string;
	display_name?: undefined | string;
	description?: undefined | string;
	keywords?: undefined | Array<string>;
	contacts?: undefined | Array<string>;
	logo_uri?: undefined | string;
	policy_uri?: undefined | string;
	information_uri?: undefined | string;
	organization_uri?: undefined | string;
	redirect_uris?: undefined | Array<string>;
	token_endpoint_auth_method?: undefined | string;
	token_endpoint_auth_signing_alg?: undefined | string;
	grant_types?: undefined | Array<string>;
	response_types?: undefined | Array<string>;
	client_name?: undefined | string;
	client_uri?: undefined | string;
	scope?: undefined | string;
	tos_uri?: undefined | string;
	sector_identifier_uri?: undefined | string;
	request_uris?: undefined | Array<string>;
	subject_type?: undefined | "public" | "pairwise";
	id_token_signed_response_alg?: undefined | string;
	id_token_encrypted_response_alg?: undefined | string;
	id_token_encrypted_response_enc?: undefined | string;
	userinfo_signed_response_alg?: undefined | string;
	userinfo_encrypted_response_alg?: undefined | string;
	userinfo_encrypted_response_enc?: undefined | string;
	request_object_signing_alg?: undefined | string;
	request_object_encryption_alg?: undefined | string;
	request_object_encryption_enc?: undefined | string;
	default_max_age?: undefined | number;
	require_auth_time?: undefined | boolean;
	default_acr_values?: undefined | Array<string>;
	initiate_login_uri?: undefined | string;
	post_logout_redirect_uris?: undefined | Array<string>;
	backchannel_token_delivery_mode?: undefined | "push" | "poll" | "ping";
	backchannel_client_notification_endpoint?: undefined | string;
	backchannel_authentication_request_signing_alg?: undefined | string;
	backchannel_user_code_parameter?: undefined | boolean;
	frontchannel_logout_uri?: undefined | string;
	frontchannel_logout_session_required?: undefined | boolean;
	backchannel_logout_uri?: undefined | string;
	backchannel_logout_session_required?: undefined | boolean;
	application_type?: undefined | "web" | "native";
	subject_types_supported?: undefined | Array<string>;
	id_token_signing_alg_values_supported?: undefined | Array<string>;
	id_token_encryption_alg_values_supported?: undefined | Array<string>;
	id_token_encryption_enc_values_supported?: undefined | Array<string>;
	userinfo_signing_alg_values_supported?: undefined | Array<string>;
	userinfo_encryption_alg_values_supported?: undefined | Array<string>;
	userinfo_encryption_enc_values_supported?: undefined | Array<string>;
	request_object_signing_alg_values_supported?: undefined | Array<string>;
	request_object_encryption_alg_values_supported?: undefined | Array<string>;
	request_object_encryption_enc_values_supported?: undefined | Array<string>;
	token_endpoint_auth_methods_supported?: undefined | Array<string>;
	token_endpoint_auth_signing_alg_values_supported?: undefined | Array<string>;
	backchannel_authentication_request_signing_alg_values_supported?: undefined | Array<string>;
	authorization_signing_alg_values_supported?: undefined | Array<string>;
	authorization_encryption_alg_values_supported?: undefined | Array<string>;
	authorization_encryption_enc_values_supported?: undefined | Array<string>;
	introspection_signing_alg_values_supported?: undefined | Array<string>;
	introspection_encryption_alg_values_supported?: undefined | Array<string>;
	introspection_encryption_enc_values_supported?: undefined | Array<string>;
	software_statement?: undefined | string;
	claims_redirect_uris?: undefined | Array<string>;
	nfv_token_signed_response_alg?: undefined | string;
	nfv_token_encrypted_response_alg?: undefined | string;
	nfv_token_encrypted_response_enc?: undefined | string;
	tls_client_certificate_bound_access_tokens?: undefined | boolean;
	tls_client_auth_subject_dn?: undefined | string;
	tls_client_auth_san_dns?: undefined | string;
	tls_client_auth_san_uri?: undefined | string;
	tls_client_auth_san_ip?: undefined | string;
	tls_client_auth_san_email?: undefined | string;
	require_signed_request_object?: undefined | boolean;
	require_pushed_authorization_requests?: undefined | boolean;
	use_mtls_endpoint_aliases?: undefined | boolean;
	authorization_details_types?: undefined | Array<string>;
	dpop_bound_access_tokens?: undefined | boolean;
	introspection_signed_response_alg?: undefined | string;
	introspection_encrypted_response_alg?: undefined | string;
	introspection_encrypted_response_enc?: undefined | string;
	authorization_signed_response_alg?: undefined | string;
	authorization_encrypted_response_alg?: undefined | string;
	authorization_encrypted_response_enc?: undefined | string;
};
```

</details>

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `client_id` | `string` | Client identifier issued or confirmed by registration; not valid in client publication metadata. |
| `client_secret?` | `undefined \| string` | Optional registration response secret; never publish it in an EC or Subordinate Statement. |
| `client_id_issued_at?` | `undefined \| number` | Nonnegative integer issuance time of the client identifier. |
| `client_secret_expires_at?` | `undefined \| number` | Nonnegative integer secret expiration; 0 means the secret does not expire. |
| `registration_access_token?` | `undefined \| string` | Optional nonempty registration-management token, returned together with registration_client_uri. The host must enforce read-only permissions when enabled. |
| `registration_client_uri?` | `undefined \| string` | HTTPS registration-management URL without a fragment, returned together with registration_access_token. |
| `jwks_uri?` | `undefined \| string` | HTTPS URL for public protocol keys, without a fragment. |
| `jwks?` | `undefined \| { [key: string]: unknown; keys: Array<JWK>; }` | JSON Web Key Set. The owning API determines whether these are Federation Entity Keys or protocol keys. |
| `software_id?` | `undefined \| string` | Client software identifier. |
| `software_version?` | `undefined \| string` | Client software version. |
| `client_registration_types?` | `undefined \| Array<string>` | Supported client registration modes. Additional string values remain permitted. |
| `signed_jwks_uri?` | `undefined \| string` | HTTPS URL for a signed protocol JWK Set, without a fragment. |
| `organization_identifier?` | `undefined \| string` | Organization identifier supplied as informational metadata. |
| `organization_name?` | `undefined \| string` | Human-readable organization name. |
| `display_name?` | `undefined \| string` | Human-readable display name. |
| `description?` | `undefined \| string` | Human-readable description. |
| `keywords?` | `undefined \| Array<string>` | Informational search keywords; a supplied list must be nonempty. |
| `contacts?` | `undefined \| Array<string>` | Contact addresses; a supplied list must be nonempty. |
| `logo_uri?` | `undefined \| string` | Logo URL for the entity or Trust Mark described by this metadata. |
| `policy_uri?` | `undefined \| string` | Policy information URL. |
| `information_uri?` | `undefined \| string` | Additional entity information URL. |
| `organization_uri?` | `undefined \| string` | Organization website URL. |
| `redirect_uris?` | `undefined \| Array<string>` | Registered redirect URLs. The effective parser enforces flow-dependent presence and redirect security rules. |
| `token_endpoint_auth_method?` | `undefined \| string` | Selected token endpoint authentication method; extension string values are preserved. |
| `token_endpoint_auth_signing_alg?` | `undefined \| string` | Signing algorithm for JWT client authentication; none is rejected. |
| `grant_types?` | `undefined \| Array<string>` | Client grant types; conditional redirect, response-type, and CIBA requirements are checked by the parser. |
| `response_types?` | `undefined \| Array<string>` | Client response types; effective metadata checks consistency with the grant types. |
| `client_name?` | `undefined \| string` | Human-readable client name. |
| `client_uri?` | `undefined \| string` | Client information URL. |
| `scope?` | `undefined \| string` | Space-separated OAuth scopes requested or registered for this client. |
| `tos_uri?` | `undefined \| string` | Client terms-of-service URL. |
| `sector_identifier_uri?` | `undefined \| string` | HTTPS URL for the client's sector identifier document. Parsing does not fetch the document. |
| `request_uris?` | `undefined \| Array<string>` | Registered Request Object URLs. |
| `subject_type?` | `undefined \| "public" \| "pairwise"` | Selected OIDC subject identifier type: public or pairwise; it must belong to any supplied subject_types_supported choices. |
| `id_token_signed_response_alg?` | `undefined \| string` | Selected signing algorithm for id token responses. |
| `id_token_encrypted_response_alg?` | `undefined \| string` | Selected key-management algorithm for id token response encryption. |
| `id_token_encrypted_response_enc?` | `undefined \| string` | Selected content-encryption method for id token responses. |
| `userinfo_signed_response_alg?` | `undefined \| string` | Selected signing algorithm for userinfo responses. |
| `userinfo_encrypted_response_alg?` | `undefined \| string` | Selected key-management algorithm for userinfo response encryption. |
| `userinfo_encrypted_response_enc?` | `undefined \| string` | Selected content-encryption method for userinfo responses. |
| `request_object_signing_alg?` | `undefined \| string` | Selected Request Object signing algorithm. |
| `request_object_encryption_alg?` | `undefined \| string` | Selected Request Object key-management algorithm. |
| `request_object_encryption_enc?` | `undefined \| string` | Selected Request Object content-encryption method. |
| `default_max_age?` | `undefined \| number` | Default authentication age in nonnegative integer seconds. |
| `require_auth_time?` | `undefined \| boolean` | Whether an authentication time claim is required by the client. |
| `default_acr_values?` | `undefined \| Array<string>` | Default requested authentication context class reference values. |
| `initiate_login_uri?` | `undefined \| string` | HTTPS URL at which the client accepts third-party initiated login. |
| `post_logout_redirect_uris?` | `undefined \| Array<string>` | Registered post-logout redirect URLs. |
| `backchannel_token_delivery_mode?` | `undefined \| "push" \| "poll" \| "ping"` | Selected CIBA mode: poll, ping, or push. Effective metadata enforces its grant and notification dependencies. |
| `backchannel_client_notification_endpoint?` | `undefined \| string` | HTTPS client notification endpoint, required for effective CIBA ping or push delivery. |
| `backchannel_authentication_request_signing_alg?` | `undefined \| string` | Signing algorithm for CIBA authentication requests. |
| `backchannel_user_code_parameter?` | `undefined \| boolean` | Whether the CIBA client uses the user_code parameter. |
| `frontchannel_logout_uri?` | `undefined \| string` | HTTPS front-channel logout URI, without a fragment. |
| `frontchannel_logout_session_required?` | `undefined \| boolean` | Whether the client requires session information for front-channel logout. |
| `backchannel_logout_uri?` | `undefined \| string` | HTTPS back-channel logout URI, without a fragment. |
| `backchannel_logout_session_required?` | `undefined \| boolean` | Whether the client requires session information for back-channel logout. |
| `application_type?` | `undefined \| "web" \| "native"` | OIDC application type: web or native. Redirect requirements depend on this value and the flow. |
| `subject_types_supported?` | `undefined \| Array<string>` | Supported OpenID Connect subject identifier types. |
| `id_token_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted id token signing algorithms. Parsing applies this field's protocol restrictions. |
| `id_token_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted id token encryption algorithms. Parsing applies this field's protocol restrictions. |
| `id_token_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted id token encryption content-encryption methods. |
| `userinfo_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted userinfo signing algorithms. Parsing applies this field's protocol restrictions. |
| `userinfo_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted userinfo encryption algorithms. Parsing applies this field's protocol restrictions. |
| `userinfo_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted userinfo encryption content-encryption methods. |
| `request_object_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted request object signing algorithms. Parsing applies this field's protocol restrictions. |
| `request_object_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted request object encryption algorithms. Parsing applies this field's protocol restrictions. |
| `request_object_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted request object encryption content-encryption methods. |
| `token_endpoint_auth_methods_supported?` | `undefined \| Array<string>` | Supported authentication methods for token endpoint. |
| `token_endpoint_auth_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted token endpoint auth signing algorithms. Parsing applies this field's protocol restrictions. |
| `backchannel_authentication_request_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted backchannel authentication request signing algorithms. Parsing applies this field's protocol restrictions. |
| `authorization_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted authorization signing algorithms. Parsing applies this field's protocol restrictions. |
| `authorization_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted authorization encryption algorithms. Parsing applies this field's protocol restrictions. |
| `authorization_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted authorization encryption content-encryption methods. |
| `introspection_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted introspection signing algorithms. Parsing applies this field's protocol restrictions. |
| `introspection_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted introspection encryption algorithms. Parsing applies this field's protocol restrictions. |
| `introspection_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted introspection encryption content-encryption methods. |
| `software_statement?` | `undefined \| string` | Software statement JWT preserved as metadata; parsing does not authenticate its signer. |
| `claims_redirect_uris?` | `undefined \| Array<string>` | Client URLs used for claims-redirection workflows. |
| `nfv_token_signed_response_alg?` | `undefined \| string` | Selected signing algorithm for nfv token responses. |
| `nfv_token_encrypted_response_alg?` | `undefined \| string` | Selected key-management algorithm for nfv token response encryption. |
| `nfv_token_encrypted_response_enc?` | `undefined \| string` | Selected content-encryption method for nfv token responses. |
| `tls_client_certificate_bound_access_tokens?` | `undefined \| boolean` | Whether this participant supports certificate-bound access tokens. |
| `tls_client_auth_subject_dn?` | `undefined \| string` | Expected certificate subject distinguished name. Effective tls_client_auth metadata requires exactly one certificate selector. |
| `tls_client_auth_san_dns?` | `undefined \| string` | Expected DNS subjectAltName. Effective tls_client_auth metadata requires exactly one certificate selector. |
| `tls_client_auth_san_uri?` | `undefined \| string` | Expected URI subjectAltName. Effective tls_client_auth metadata requires exactly one certificate selector. |
| `tls_client_auth_san_ip?` | `undefined \| string` | Expected IP subjectAltName. Effective tls_client_auth metadata requires exactly one certificate selector. |
| `tls_client_auth_san_email?` | `undefined \| string` | Expected email subjectAltName. Effective tls_client_auth metadata requires exactly one certificate selector. |
| `require_signed_request_object?` | `undefined \| boolean` | Whether Request Objects must be signed. |
| `require_pushed_authorization_requests?` | `undefined \| boolean` | Whether clients must use PAR. |
| `use_mtls_endpoint_aliases?` | `undefined \| boolean` | Whether the client requests the server's mutual-TLS endpoint aliases. |
| `authorization_details_types?` | `undefined \| Array<string>` | Authorization-details types requested by the client. |
| `dpop_bound_access_tokens?` | `undefined \| boolean` | Whether the client requests DPoP-bound access tokens. |
| `introspection_signed_response_alg?` | `undefined \| string` | Selected signing algorithm for introspection responses. |
| `introspection_encrypted_response_alg?` | `undefined \| string` | Selected key-management algorithm for introspection response encryption. |
| `introspection_encrypted_response_enc?` | `undefined \| string` | Selected content-encryption method for introspection responses. |
| `authorization_signed_response_alg?` | `undefined \| string` | Selected signing algorithm for authorization responses. |
| `authorization_encrypted_response_alg?` | `undefined \| string` | Selected key-management algorithm for authorization response encryption. |
| `authorization_encrypted_response_enc?` | `undefined \| string` | Selected content-encryption method for authorization responses. |

## `OAuthResourceMetadata`

[Source](../../../packages/oidc/src/schemas/metadata.ts#L665)

Resource metadata as a Federation Entity Type, where resource is optional. OAuthResourceRole.parseMetadata uses this default profile; pass profile: rfc9728 when validating a complete protected-resource metadata document, which requires resource. Parsing does not fetch the resource or its keys, validate a token, or authenticate signed_metadata.

<details>
<summary>Type declaration</summary>

```typescript signature
type OAuthResourceMetadata = {
	[key: string]: unknown;
	signed_jwks_uri?: undefined | string;
	organization_identifier?: undefined | string;
	organization_name?: undefined | string;
	display_name?: undefined | string;
	description?: undefined | string;
	keywords?: undefined | Array<string>;
	contacts?: undefined | Array<string>;
	logo_uri?: undefined | string;
	policy_uri?: undefined | string;
	information_uri?: undefined | string;
	organization_uri?: undefined | string;
	resource?: undefined | string;
	resource_name?: undefined | string;
	resource_documentation?: undefined | string;
	resource_policy_uri?: undefined | string;
	resource_tos_uri?: undefined | string;
	tls_client_certificate_bound_access_tokens?: undefined | boolean;
	authorization_details_types_supported?: undefined | Array<string>;
	dpop_bound_access_tokens_required?: undefined | boolean;
	signed_metadata?: undefined | string;
	authorization_servers?: undefined | Array<string>;
	bearer_methods_supported?: undefined | Array<"query" | "body" | "header">;
	resource_signing_alg_values_supported?: undefined | Array<string>;
	dpop_signing_alg_values_supported?: undefined | Array<string>;
	scopes_supported?: undefined | Array<string>;
	jwks_uri?: undefined | string;
	jwks?: undefined | { [key: string]: unknown; keys: Array<JWK>; };
};
```

</details>

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `signed_jwks_uri?` | `undefined \| string` | HTTPS URL for a signed protocol JWK Set, without a fragment. |
| `organization_identifier?` | `undefined \| string` | Organization identifier supplied as informational metadata. |
| `organization_name?` | `undefined \| string` | Human-readable organization name. |
| `display_name?` | `undefined \| string` | Human-readable display name. |
| `description?` | `undefined \| string` | Human-readable description. |
| `keywords?` | `undefined \| Array<string>` | Informational search keywords; a supplied list must be nonempty. |
| `contacts?` | `undefined \| Array<string>` | Contact addresses; a supplied list must be nonempty. |
| `logo_uri?` | `undefined \| string` | Logo URL for the entity or Trust Mark described by this metadata. |
| `policy_uri?` | `undefined \| string` | Policy information URL. |
| `information_uri?` | `undefined \| string` | Additional entity information URL. |
| `organization_uri?` | `undefined \| string` | Organization website URL. |
| `resource?` | `undefined \| string` | HTTPS resource identifier without a fragment. Optional in federation metadata; required by the rfc9728 document parser profile. |
| `resource_name?` | `undefined \| string` | Human-readable protected-resource name. |
| `resource_documentation?` | `undefined \| string` | URL documenting the protected resource. |
| `resource_policy_uri?` | `undefined \| string` | Protected resource's policy URL. |
| `resource_tos_uri?` | `undefined \| string` | Protected resource's terms-of-service URL. |
| `tls_client_certificate_bound_access_tokens?` | `undefined \| boolean` | Whether this participant supports certificate-bound access tokens. |
| `authorization_details_types_supported?` | `undefined \| Array<string>` | Supported authorization_details type values. |
| `dpop_bound_access_tokens_required?` | `undefined \| boolean` | Whether the resource requires DPoP-bound access tokens. |
| `signed_metadata?` | `undefined \| string` | Signed metadata JWT preserved as metadata; parsing does not verify its signature. |
| `authorization_servers?` | `undefined \| Array<string>` | HTTPS authorization-server issuer identifiers without query or fragment. |
| `bearer_methods_supported?` | `undefined \| Array<"query" \| "body" \| "header">` | Bearer-token presentation methods: header, body, or query. |
| `resource_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted resource signing algorithms. Parsing applies this field's protocol restrictions. |
| `dpop_signing_alg_values_supported?` | `undefined \| Array<string>` | Supported asymmetric DPoP signing algorithms; none and symmetric HMAC algorithms are rejected. |
| `scopes_supported?` | `undefined \| Array<string>` | Supported OAuth scopes. |
| `jwks_uri?` | `undefined \| string` | HTTPS URL for public protocol keys, without a fragment. |
| `jwks?` | `undefined \| { [key: string]: unknown; keys: Array<JWK>; }` | JSON Web Key Set. The owning API determines whether these are Federation Entity Keys or protocol keys. |

## `OAuthResourcePublicationMetadata`

[Source](../../../packages/oidc/src/schemas/metadata.ts#L694)

Publication form of resource metadata, using the same optional field shape as the Federation resource profile. OAuthResourceRole.parsePublicationMetadata validates supplied values and mixed-key use requirements without requiring a full RFC 9728 document.

<details>
<summary>Type declaration</summary>

```typescript signature
type OAuthResourcePublicationMetadata = {
	[key: string]: unknown;
	signed_jwks_uri?: undefined | string;
	organization_identifier?: undefined | string;
	organization_name?: undefined | string;
	display_name?: undefined | string;
	description?: undefined | string;
	keywords?: undefined | Array<string>;
	contacts?: undefined | Array<string>;
	logo_uri?: undefined | string;
	policy_uri?: undefined | string;
	information_uri?: undefined | string;
	organization_uri?: undefined | string;
	resource?: undefined | string;
	resource_name?: undefined | string;
	resource_documentation?: undefined | string;
	resource_policy_uri?: undefined | string;
	resource_tos_uri?: undefined | string;
	tls_client_certificate_bound_access_tokens?: undefined | boolean;
	authorization_details_types_supported?: undefined | Array<string>;
	dpop_bound_access_tokens_required?: undefined | boolean;
	signed_metadata?: undefined | string;
	authorization_servers?: undefined | Array<string>;
	bearer_methods_supported?: undefined | Array<"query" | "body" | "header">;
	resource_signing_alg_values_supported?: undefined | Array<string>;
	dpop_signing_alg_values_supported?: undefined | Array<string>;
	scopes_supported?: undefined | Array<string>;
	jwks_uri?: undefined | string;
	jwks?: undefined | { [key: string]: unknown; keys: Array<JWK>; };
};
```

</details>

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `signed_jwks_uri?` | `undefined \| string` | HTTPS URL for a signed protocol JWK Set, without a fragment. |
| `organization_identifier?` | `undefined \| string` | Organization identifier supplied as informational metadata. |
| `organization_name?` | `undefined \| string` | Human-readable organization name. |
| `display_name?` | `undefined \| string` | Human-readable display name. |
| `description?` | `undefined \| string` | Human-readable description. |
| `keywords?` | `undefined \| Array<string>` | Informational search keywords; a supplied list must be nonempty. |
| `contacts?` | `undefined \| Array<string>` | Contact addresses; a supplied list must be nonempty. |
| `logo_uri?` | `undefined \| string` | Logo URL for the entity or Trust Mark described by this metadata. |
| `policy_uri?` | `undefined \| string` | Policy information URL. |
| `information_uri?` | `undefined \| string` | Additional entity information URL. |
| `organization_uri?` | `undefined \| string` | Organization website URL. |
| `resource?` | `undefined \| string` | HTTPS resource identifier without a fragment. Optional in federation metadata; required by the rfc9728 document parser profile. |
| `resource_name?` | `undefined \| string` | Human-readable protected-resource name. |
| `resource_documentation?` | `undefined \| string` | URL documenting the protected resource. |
| `resource_policy_uri?` | `undefined \| string` | Protected resource's policy URL. |
| `resource_tos_uri?` | `undefined \| string` | Protected resource's terms-of-service URL. |
| `tls_client_certificate_bound_access_tokens?` | `undefined \| boolean` | Whether this participant supports certificate-bound access tokens. |
| `authorization_details_types_supported?` | `undefined \| Array<string>` | Supported authorization_details type values. |
| `dpop_bound_access_tokens_required?` | `undefined \| boolean` | Whether the resource requires DPoP-bound access tokens. |
| `signed_metadata?` | `undefined \| string` | Signed metadata JWT preserved as metadata; parsing does not verify its signature. |
| `authorization_servers?` | `undefined \| Array<string>` | HTTPS authorization-server issuer identifiers without query or fragment. |
| `bearer_methods_supported?` | `undefined \| Array<"query" \| "body" \| "header">` | Bearer-token presentation methods: header, body, or query. |
| `resource_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted resource signing algorithms. Parsing applies this field's protocol restrictions. |
| `dpop_signing_alg_values_supported?` | `undefined \| Array<string>` | Supported asymmetric DPoP signing algorithms; none and symmetric HMAC algorithms are rejected. |
| `scopes_supported?` | `undefined \| Array<string>` | Supported OAuth scopes. |
| `jwks_uri?` | `undefined \| string` | HTTPS URL for public protocol keys, without a fragment. |
| `jwks?` | `undefined \| { [key: string]: unknown; keys: Array<JWK>; }` | JSON Web Key Set. The owning API determines whether these are Federation Entity Keys or protocol keys. |

## `OIDCFederationMetadata`

[Source](../../../packages/oidc/src/schemas/metadata.ts#L718)

Federation Entity Type map whose OIDC/OAuth blocks use effective metadata types. This is a TypeScript contract; there is no public aggregate parser or exported schema object with this name. Validate each protocol block through the matching public role, and use core APIs for Federation signature, policy, and trust checks. Wallet blocks remain loose records here.

```typescript signature
type OIDCFederationMetadata = FederationMetadata & {
	readonly federation_entity?: FederationEntityMetadata;
	readonly openid_relying_party?: OpenIDRelyingPartyMetadata;
	readonly openid_provider?: OpenIDProviderMetadata;
	readonly oauth_authorization_server?: OAuthAuthorizationServerMetadata;
	readonly oauth_client?: OAuthClientMetadata;
	readonly oauth_resource?: OAuthResourceMetadata;
};
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `federation_entity?` | `FederationEntityMetadata` | Federation endpoint and informational metadata. Unknown extension blocks are preserved. |
| `openid_relying_party?` | `OpenIDRelyingPartyMetadata` | OpenID Relying Party metadata. Unknown extension blocks are preserved. |
| `openid_provider?` | `OpenIDProviderMetadata` | OpenID Provider metadata. Unknown extension blocks are preserved. |
| `oauth_authorization_server?` | `OAuthAuthorizationServerMetadata` | OAuth authorization-server metadata. Unknown extension blocks are preserved. |
| `oauth_client?` | `OAuthClientMetadata` | OAuth client metadata. Unknown extension blocks are preserved. |
| `oauth_resource?` | `OAuthResourceMetadata` | OAuth protected-resource metadata. Unknown extension blocks are preserved. |
| `openid_wallet_provider?` | `undefined \| Record<string, unknown>` | Wallet Provider metadata, left as a loose block by OIDC. Unknown extension blocks are preserved. |
| `openid_credential_issuer?` | `undefined \| Record<string, unknown>` | Credential Issuer metadata, left as a loose block by OIDC. Unknown extension blocks are preserved. |
| `openid_credential_verifier?` | `undefined \| Record<string, unknown>` | Credential Verifier metadata, left as a loose block by OIDC. Unknown extension blocks are preserved. |

## `OIDCFederationPublicationMetadata`

[Source](../../../packages/oidc/src/schemas/metadata.ts#L735)

Federation metadata map using publication types for the OIDC/OAuth blocks. This type permits missing protocol requirements that a Superior may complete. It is not an aggregate public parser, and wallet blocks retain the core Federation shape rather than wallet protocol validation.

```typescript signature
type OIDCFederationPublicationMetadata = FederationMetadata & {
	readonly openid_relying_party?: OpenIDRelyingPartyPublicationMetadata;
	readonly openid_provider?: OpenIDProviderPublicationMetadata;
	readonly oauth_authorization_server?: OAuthAuthorizationServerPublicationMetadata;
	readonly oauth_client?: OAuthClientPublicationMetadata;
	readonly oauth_resource?: OAuthResourcePublicationMetadata;
};
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `federation_entity?` | `undefined \| FederationEntityMetadata` | Federation endpoint and informational metadata. Unknown extension blocks are preserved. |
| `openid_relying_party?` | `OpenIDRelyingPartyPublicationMetadata` | OpenID Relying Party metadata. Unknown extension blocks are preserved. |
| `openid_provider?` | `OpenIDProviderPublicationMetadata` | OpenID Provider metadata. Unknown extension blocks are preserved. |
| `oauth_authorization_server?` | `OAuthAuthorizationServerPublicationMetadata` | OAuth authorization-server metadata. Unknown extension blocks are preserved. |
| `oauth_client?` | `OAuthClientPublicationMetadata` | OAuth client metadata. Unknown extension blocks are preserved. |
| `oauth_resource?` | `OAuthResourcePublicationMetadata` | OAuth protected-resource metadata. Unknown extension blocks are preserved. |
| `openid_wallet_provider?` | `undefined \| Record<string, unknown>` | Wallet Provider metadata, left as a loose block by OIDC. Unknown extension blocks are preserved. |
| `openid_credential_issuer?` | `undefined \| Record<string, unknown>` | Credential Issuer metadata, left as a loose block by OIDC. Unknown extension blocks are preserved. |
| `openid_credential_verifier?` | `undefined \| Record<string, unknown>` | Credential Verifier metadata, left as a loose block by OIDC. Unknown extension blocks are preserved. |

## `OpenIDProviderMetadata`

[Source](../../../packages/oidc/src/schemas/metadata.ts#L546)

Effective OP metadata, validated through OidcProviderRole.parseMetadata. The parser combines OP and shared AS checks, including required issuer, authorization endpoint, response types, subject types, RS256 support, and a public-key representation. Conditional token, explicit-registration, CIBA, and attestation requirements also apply. A standalone parse does not bind issuer to an independently known Entity Identifier; federation-aware consumption performs that check.

<details>
<summary>Type declaration</summary>

```typescript signature
type OpenIDProviderMetadata = {
	[key: string]: unknown;
	issuer: string;
	authorization_endpoint: string;
	response_types_supported: Array<string>;
	subject_types_supported: ("public" | "pairwise")[] & string[];
	id_token_signing_alg_values_supported: Array<string>;
	client_registration_types_supported?: undefined | Array<string>;
	federation_registration_endpoint?: undefined | string;
	signed_jwks_uri?: undefined | string;
	organization_identifier?: undefined | string;
	check_session_iframe?: undefined | string;
	backchannel_authentication_request_signing_alg_values_supported?: undefined | Array<string>;
	authorization_signing_alg_values_supported?: undefined | Array<string>;
	authorization_encryption_alg_values_supported?: undefined | Array<string>;
	authorization_encryption_enc_values_supported?: undefined | Array<string>;
	organization_name?: undefined | string;
	display_name?: undefined | string;
	description?: undefined | string;
	keywords?: undefined | Array<string>;
	contacts?: undefined | Array<string>;
	logo_uri?: undefined | string;
	policy_uri?: undefined | string;
	information_uri?: undefined | string;
	organization_uri?: undefined | string;
	token_endpoint?: undefined | string;
	userinfo_endpoint?: undefined | string;
	jwks_uri?: undefined | string;
	jwks?: undefined | { [key: string]: unknown; keys: Array<JWK>; };
	registration_endpoint?: undefined | string;
	scopes_supported?: undefined | Array<string>;
	response_modes_supported?: undefined | Array<string>;
	grant_types_supported?: undefined | Array<string>;
	acr_values_supported?: undefined | Array<string>;
	id_token_encryption_alg_values_supported?: undefined | Array<string>;
	id_token_encryption_enc_values_supported?: undefined | Array<string>;
	userinfo_signing_alg_values_supported?: undefined | Array<string>;
	userinfo_encryption_alg_values_supported?: undefined | Array<string>;
	userinfo_encryption_enc_values_supported?: undefined | Array<string>;
	request_object_signing_alg_values_supported?: undefined | Array<string>;
	request_object_encryption_alg_values_supported?: undefined | Array<string>;
	request_object_encryption_enc_values_supported?: undefined | Array<string>;
	token_endpoint_auth_methods_supported?: undefined | Array<string>;
	token_endpoint_auth_signing_alg_values_supported?: undefined | Array<string>;
	display_values_supported?: undefined | Array<string>;
	claim_types_supported?: undefined | Array<string>;
	claims_supported?: undefined | Array<string>;
	service_documentation?: undefined | string;
	claims_locales_supported?: undefined | Array<string>;
	ui_locales_supported?: undefined | Array<string>;
	claims_parameter_supported?: undefined | boolean;
	request_parameter_supported?: undefined | boolean;
	request_uri_parameter_supported?: undefined | boolean;
	require_request_uri_registration?: undefined | boolean;
	op_policy_uri?: undefined | string;
	op_tos_uri?: undefined | string;
	end_session_endpoint?: undefined | string;
	frontchannel_logout_supported?: undefined | boolean;
	frontchannel_logout_session_supported?: undefined | boolean;
	backchannel_logout_supported?: undefined | boolean;
	backchannel_logout_session_supported?: undefined | boolean;
	backchannel_token_delivery_modes_supported?: undefined | string[] & ("push" | "poll" | "ping")[];
	backchannel_authentication_endpoint?: undefined | string;
	backchannel_user_code_parameter_supported?: undefined | boolean;
	client_attestation_signing_alg_values_supported?: undefined | Array<string>;
	client_attestation_pop_signing_alg_values_supported?: undefined | Array<string>;
	challenge_endpoint?: undefined | string;
	revocation_endpoint?: undefined | string;
	revocation_endpoint_auth_methods_supported?: undefined | Array<string>;
	revocation_endpoint_auth_signing_alg_values_supported?: undefined | Array<string>;
	introspection_endpoint?: undefined | string;
	introspection_endpoint_auth_methods_supported?: undefined | Array<string>;
	introspection_endpoint_auth_signing_alg_values_supported?: undefined | Array<string>;
	introspection_signing_alg_values_supported?: undefined | Array<string>;
	introspection_encryption_alg_values_supported?: undefined | Array<string>;
	introspection_encryption_enc_values_supported?: undefined | Array<string>;
	nfv_token_signing_alg_values_supported?: undefined | Array<string>;
	nfv_token_encryption_alg_values_supported?: undefined | Array<string>;
	nfv_token_encryption_enc_values_supported?: undefined | Array<string>;
	code_challenge_methods_supported?: undefined | Array<string>;
	device_authorization_endpoint?: undefined | string;
	pushed_authorization_request_endpoint?: undefined | string;
	require_pushed_authorization_requests?: undefined | boolean;
	require_signed_request_object?: undefined | boolean;
	dpop_signing_alg_values_supported?: undefined | Array<string>;
	authorization_response_iss_parameter_supported?: undefined | boolean;
	authorization_details_types_supported?: undefined | Array<string>;
	protected_resources?: undefined | Array<string>;
	tls_client_certificate_bound_access_tokens?: undefined | boolean;
	mtls_endpoint_aliases?: undefined | { [key: string]: unknown; token_endpoint?: undefined | string; revocation_endpoint?: undefined | string; introspection_endpoint?: undefined | string; device_authorization_endpoint?: undefined | string; pushed_authorization_request_endpoint?: undefined | string; userinfo_endpoint?: undefined | string; backchannel_authentication_endpoint?: undefined | string; };
	signed_metadata?: undefined | string;
};
```

</details>

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `issuer` | `string` | Protocol issuer URL. Federation consumers additionally bind it to the Entity Identifier. |
| `authorization_endpoint` | `string` | HTTPS endpoint for authorization requests; no fragment is allowed. |
| `response_types_supported` | `Array<string>` | Supported OAuth response types; required for the normal effective AS profile. |
| `subject_types_supported` | `("public" \| "pairwise")[] & string[]` | Supported OpenID Connect subject identifier types. |
| `id_token_signing_alg_values_supported` | `Array<string>` | Permitted id token signing algorithms. Parsing applies this field's protocol restrictions. |
| `client_registration_types_supported?` | `undefined \| Array<string>` | Supported registration modes; extension values are permitted. |
| `federation_registration_endpoint?` | `undefined \| string` | Federation-specific registration URL; effective metadata requires an HTTPS, fragment-free value when explicit registration is supported. |
| `signed_jwks_uri?` | `undefined \| string` | HTTPS URL for a signed protocol JWK Set, without a fragment. |
| `organization_identifier?` | `undefined \| string` | Organization identifier supplied as informational metadata. |
| `check_session_iframe?` | `undefined \| string` | HTTPS session-management iframe URL. |
| `backchannel_authentication_request_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted backchannel authentication request signing algorithms. Parsing applies this field's protocol restrictions. |
| `authorization_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted authorization signing algorithms. Parsing applies this field's protocol restrictions. |
| `authorization_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted authorization encryption algorithms. Parsing applies this field's protocol restrictions. |
| `authorization_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted authorization encryption content-encryption methods. |
| `organization_name?` | `undefined \| string` | Human-readable organization name. |
| `display_name?` | `undefined \| string` | Human-readable display name. |
| `description?` | `undefined \| string` | Human-readable description. |
| `keywords?` | `undefined \| Array<string>` | Informational search keywords; a supplied list must be nonempty. |
| `contacts?` | `undefined \| Array<string>` | Contact addresses; a supplied list must be nonempty. |
| `logo_uri?` | `undefined \| string` | Logo URL for the entity or Trust Mark described by this metadata. |
| `policy_uri?` | `undefined \| string` | Policy information URL. |
| `information_uri?` | `undefined \| string` | Additional entity information URL. |
| `organization_uri?` | `undefined \| string` | Organization website URL. |
| `token_endpoint?` | `undefined \| string` | HTTPS token endpoint; required in effective metadata unless only implicit is supported. |
| `userinfo_endpoint?` | `undefined \| string` | HTTPS OpenID Connect UserInfo endpoint. |
| `jwks_uri?` | `undefined \| string` | HTTPS URL for public protocol keys, without a fragment. |
| `jwks?` | `undefined \| { [key: string]: unknown; keys: Array<JWK>; }` | JSON Web Key Set. The owning API determines whether these are Federation Entity Keys or protocol keys. |
| `registration_endpoint?` | `undefined \| string` | HTTPS dynamic client registration endpoint. |
| `scopes_supported?` | `undefined \| Array<string>` | Supported OAuth scopes. |
| `response_modes_supported?` | `undefined \| Array<string>` | Supported authorization response modes. |
| `grant_types_supported?` | `undefined \| Array<string>` | Supported OAuth grant types; omitted values use the protocol's default when evaluating conditional requirements. |
| `acr_values_supported?` | `undefined \| Array<string>` | Supported authentication context class reference values. |
| `id_token_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted id token encryption algorithms. Parsing applies this field's protocol restrictions. |
| `id_token_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted id token encryption content-encryption methods. |
| `userinfo_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted userinfo signing algorithms. Parsing applies this field's protocol restrictions. |
| `userinfo_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted userinfo encryption algorithms. Parsing applies this field's protocol restrictions. |
| `userinfo_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted userinfo encryption content-encryption methods. |
| `request_object_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted request object signing algorithms. Parsing applies this field's protocol restrictions. |
| `request_object_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted request object encryption algorithms. Parsing applies this field's protocol restrictions. |
| `request_object_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted request object encryption content-encryption methods. |
| `token_endpoint_auth_methods_supported?` | `undefined \| Array<string>` | Supported authentication methods for token endpoint. |
| `token_endpoint_auth_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted token endpoint auth signing algorithms. Parsing applies this field's protocol restrictions. |
| `display_values_supported?` | `undefined \| Array<string>` | Supported OpenID Connect display modes. |
| `claim_types_supported?` | `undefined \| Array<string>` | Supported OpenID Connect claim representations. |
| `claims_supported?` | `undefined \| Array<string>` | Supported claim names. |
| `service_documentation?` | `undefined \| string` | URL for documentation of this authorization server. |
| `claims_locales_supported?` | `undefined \| Array<string>` | Supported languages for returned claims. |
| `ui_locales_supported?` | `undefined \| Array<string>` | Supported languages for the user interface. |
| `claims_parameter_supported?` | `undefined \| boolean` | Whether the OpenID Connect claims request parameter is supported. |
| `request_parameter_supported?` | `undefined \| boolean` | Whether a Request Object can be sent using the request parameter. |
| `request_uri_parameter_supported?` | `undefined \| boolean` | Whether Request Objects can be referenced using request_uri. |
| `require_request_uri_registration?` | `undefined \| boolean` | Whether Request Object URIs must be registered in advance. |
| `op_policy_uri?` | `undefined \| string` | URL for the provider's privacy policy. |
| `op_tos_uri?` | `undefined \| string` | URL for the provider's terms of service. |
| `end_session_endpoint?` | `undefined \| string` | HTTPS endpoint for initiating logout. |
| `frontchannel_logout_supported?` | `undefined \| boolean` | Whether front-channel logout is supported. |
| `frontchannel_logout_session_supported?` | `undefined \| boolean` | Whether front-channel logout supports session identifiers. |
| `backchannel_logout_supported?` | `undefined \| boolean` | Whether back-channel logout is supported. |
| `backchannel_logout_session_supported?` | `undefined \| boolean` | Whether back-channel logout supports session identifiers. |
| `backchannel_token_delivery_modes_supported?` | `undefined \| string[] & ("push" \| "poll" \| "ping")[]` | Supported CIBA delivery modes: poll, ping, or push. |
| `backchannel_authentication_endpoint?` | `undefined \| string` | HTTPS endpoint for CIBA authentication requests. |
| `backchannel_user_code_parameter_supported?` | `undefined \| boolean` | Whether CIBA requests support the user_code parameter. |
| `client_attestation_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted client attestation signing algorithms. Parsing applies this field's protocol restrictions. |
| `client_attestation_pop_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted client attestation pop signing algorithms. Parsing applies this field's protocol restrictions. |
| `challenge_endpoint?` | `undefined \| string` | Client-attestation challenge endpoint URL; this schema checks URL syntax, not endpoint trust. |
| `revocation_endpoint?` | `undefined \| string` | HTTPS endpoint for token revocation. |
| `revocation_endpoint_auth_methods_supported?` | `undefined \| Array<string>` | Supported authentication methods for revocation endpoint. |
| `revocation_endpoint_auth_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted revocation endpoint auth signing algorithms. Parsing applies this field's protocol restrictions. |
| `introspection_endpoint?` | `undefined \| string` | HTTPS endpoint for token introspection. |
| `introspection_endpoint_auth_methods_supported?` | `undefined \| Array<string>` | Supported authentication methods for introspection endpoint. |
| `introspection_endpoint_auth_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted introspection endpoint auth signing algorithms. Parsing applies this field's protocol restrictions. |
| `introspection_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted introspection signing algorithms. Parsing applies this field's protocol restrictions. |
| `introspection_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted introspection encryption algorithms. Parsing applies this field's protocol restrictions. |
| `introspection_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted introspection encryption content-encryption methods. |
| `nfv_token_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted nfv token signing algorithms. Parsing applies this field's protocol restrictions. |
| `nfv_token_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted nfv token encryption algorithms. Parsing applies this field's protocol restrictions. |
| `nfv_token_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted nfv token encryption content-encryption methods. |
| `code_challenge_methods_supported?` | `undefined \| Array<string>` | Supported PKCE code challenge methods. |
| `device_authorization_endpoint?` | `undefined \| string` | HTTPS device authorization endpoint, without a fragment. |
| `pushed_authorization_request_endpoint?` | `undefined \| string` | HTTPS Pushed Authorization Request endpoint, without a fragment. |
| `require_pushed_authorization_requests?` | `undefined \| boolean` | Whether clients must use PAR. |
| `require_signed_request_object?` | `undefined \| boolean` | Whether Request Objects must be signed. |
| `dpop_signing_alg_values_supported?` | `undefined \| Array<string>` | Supported asymmetric DPoP signing algorithms; none and symmetric HMAC algorithms are rejected. |
| `authorization_response_iss_parameter_supported?` | `undefined \| boolean` | Whether authorization responses support an issuer identifier parameter. |
| `authorization_details_types_supported?` | `undefined \| Array<string>` | Supported authorization_details type values. |
| `protected_resources?` | `undefined \| Array<string>` | Protected-resource identifiers served by this authorization server. |
| `tls_client_certificate_bound_access_tokens?` | `undefined \| boolean` | Whether this participant supports certificate-bound access tokens. |
| `mtls_endpoint_aliases?` | `undefined \| { [key: string]: unknown; token_endpoint?: undefined \| string; revocation_endpoint?: undefined \| string; introspection_endpoint?: undefined \| string; device_authorization_endpoint?: undefined \| string; pushed_authorization_request_endpoint?: undefined \| string; userinfo_endpoint?: undefined \| string; backchannel_authentication_endpoint?: undefined \| string; }` | Optional HTTPS endpoint aliases for mutual-TLS access. Unknown extension aliases are preserved. |
| `signed_metadata?` | `undefined \| string` | Signed metadata JWT preserved as metadata; parsing does not verify its signature. |

## `OpenIDProviderPublicationMetadata`

[Source](../../../packages/oidc/src/schemas/metadata.ts#L687)

Partial OP publication metadata. The role publication parser checks supplied values while allowing a Superior to complete requirements. Missing fields in this type are permitted for publication, not proof that the same object is valid effective OP metadata.

<details>
<summary>Type declaration</summary>

```typescript signature
type OpenIDProviderPublicationMetadata = {
	[key: string]: unknown;
	client_registration_types_supported?: undefined | Array<string>;
	federation_registration_endpoint?: undefined | string;
	signed_jwks_uri?: undefined | string;
	organization_identifier?: undefined | string;
	check_session_iframe?: undefined | string;
	backchannel_authentication_request_signing_alg_values_supported?: undefined | Array<string>;
	authorization_signing_alg_values_supported?: undefined | Array<string>;
	authorization_encryption_alg_values_supported?: undefined | Array<string>;
	authorization_encryption_enc_values_supported?: undefined | Array<string>;
	organization_name?: undefined | string;
	display_name?: undefined | string;
	description?: undefined | string;
	keywords?: undefined | Array<string>;
	contacts?: undefined | Array<string>;
	logo_uri?: undefined | string;
	policy_uri?: undefined | string;
	information_uri?: undefined | string;
	organization_uri?: undefined | string;
	issuer?: undefined | string;
	authorization_endpoint?: undefined | string;
	token_endpoint?: undefined | string;
	userinfo_endpoint?: undefined | string;
	jwks_uri?: undefined | string;
	jwks?: undefined | { [key: string]: unknown; keys: Array<JWK>; };
	registration_endpoint?: undefined | string;
	scopes_supported?: undefined | Array<string>;
	response_types_supported?: undefined | Array<string>;
	response_modes_supported?: undefined | Array<string>;
	grant_types_supported?: undefined | Array<string>;
	acr_values_supported?: undefined | Array<string>;
	subject_types_supported?: undefined | ("public" | "pairwise")[] & string[];
	id_token_signing_alg_values_supported?: undefined | Array<string>;
	id_token_encryption_alg_values_supported?: undefined | Array<string>;
	id_token_encryption_enc_values_supported?: undefined | Array<string>;
	userinfo_signing_alg_values_supported?: undefined | Array<string>;
	userinfo_encryption_alg_values_supported?: undefined | Array<string>;
	userinfo_encryption_enc_values_supported?: undefined | Array<string>;
	request_object_signing_alg_values_supported?: undefined | Array<string>;
	request_object_encryption_alg_values_supported?: undefined | Array<string>;
	request_object_encryption_enc_values_supported?: undefined | Array<string>;
	token_endpoint_auth_methods_supported?: undefined | Array<string>;
	token_endpoint_auth_signing_alg_values_supported?: undefined | Array<string>;
	display_values_supported?: undefined | Array<string>;
	claim_types_supported?: undefined | Array<string>;
	claims_supported?: undefined | Array<string>;
	service_documentation?: undefined | string;
	claims_locales_supported?: undefined | Array<string>;
	ui_locales_supported?: undefined | Array<string>;
	claims_parameter_supported?: undefined | boolean;
	request_parameter_supported?: undefined | boolean;
	request_uri_parameter_supported?: undefined | boolean;
	require_request_uri_registration?: undefined | boolean;
	op_policy_uri?: undefined | string;
	op_tos_uri?: undefined | string;
	end_session_endpoint?: undefined | string;
	frontchannel_logout_supported?: undefined | boolean;
	frontchannel_logout_session_supported?: undefined | boolean;
	backchannel_logout_supported?: undefined | boolean;
	backchannel_logout_session_supported?: undefined | boolean;
	backchannel_token_delivery_modes_supported?: undefined | string[] & ("push" | "poll" | "ping")[];
	backchannel_authentication_endpoint?: undefined | string;
	backchannel_user_code_parameter_supported?: undefined | boolean;
	client_attestation_signing_alg_values_supported?: undefined | Array<string>;
	client_attestation_pop_signing_alg_values_supported?: undefined | Array<string>;
	challenge_endpoint?: undefined | string;
	revocation_endpoint?: undefined | string;
	revocation_endpoint_auth_methods_supported?: undefined | Array<string>;
	revocation_endpoint_auth_signing_alg_values_supported?: undefined | Array<string>;
	introspection_endpoint?: undefined | string;
	introspection_endpoint_auth_methods_supported?: undefined | Array<string>;
	introspection_endpoint_auth_signing_alg_values_supported?: undefined | Array<string>;
	introspection_signing_alg_values_supported?: undefined | Array<string>;
	introspection_encryption_alg_values_supported?: undefined | Array<string>;
	introspection_encryption_enc_values_supported?: undefined | Array<string>;
	nfv_token_signing_alg_values_supported?: undefined | Array<string>;
	nfv_token_encryption_alg_values_supported?: undefined | Array<string>;
	nfv_token_encryption_enc_values_supported?: undefined | Array<string>;
	code_challenge_methods_supported?: undefined | Array<string>;
	device_authorization_endpoint?: undefined | string;
	pushed_authorization_request_endpoint?: undefined | string;
	require_pushed_authorization_requests?: undefined | boolean;
	require_signed_request_object?: undefined | boolean;
	dpop_signing_alg_values_supported?: undefined | Array<string>;
	authorization_response_iss_parameter_supported?: undefined | boolean;
	authorization_details_types_supported?: undefined | Array<string>;
	protected_resources?: undefined | Array<string>;
	tls_client_certificate_bound_access_tokens?: undefined | boolean;
	mtls_endpoint_aliases?: undefined | { [key: string]: unknown; token_endpoint?: undefined | string; revocation_endpoint?: undefined | string; introspection_endpoint?: undefined | string; device_authorization_endpoint?: undefined | string; pushed_authorization_request_endpoint?: undefined | string; userinfo_endpoint?: undefined | string; backchannel_authentication_endpoint?: undefined | string; };
	signed_metadata?: undefined | string;
};
```

</details>

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `client_registration_types_supported?` | `undefined \| Array<string>` | Supported registration modes; extension values are permitted. |
| `federation_registration_endpoint?` | `undefined \| string` | Federation-specific registration URL; effective metadata requires an HTTPS, fragment-free value when explicit registration is supported. |
| `signed_jwks_uri?` | `undefined \| string` | HTTPS URL for a signed protocol JWK Set, without a fragment. |
| `organization_identifier?` | `undefined \| string` | Organization identifier supplied as informational metadata. |
| `check_session_iframe?` | `undefined \| string` | HTTPS session-management iframe URL. |
| `backchannel_authentication_request_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted backchannel authentication request signing algorithms. Parsing applies this field's protocol restrictions. |
| `authorization_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted authorization signing algorithms. Parsing applies this field's protocol restrictions. |
| `authorization_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted authorization encryption algorithms. Parsing applies this field's protocol restrictions. |
| `authorization_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted authorization encryption content-encryption methods. |
| `organization_name?` | `undefined \| string` | Human-readable organization name. |
| `display_name?` | `undefined \| string` | Human-readable display name. |
| `description?` | `undefined \| string` | Human-readable description. |
| `keywords?` | `undefined \| Array<string>` | Informational search keywords; a supplied list must be nonempty. |
| `contacts?` | `undefined \| Array<string>` | Contact addresses; a supplied list must be nonempty. |
| `logo_uri?` | `undefined \| string` | Logo URL for the entity or Trust Mark described by this metadata. |
| `policy_uri?` | `undefined \| string` | Policy information URL. |
| `information_uri?` | `undefined \| string` | Additional entity information URL. |
| `organization_uri?` | `undefined \| string` | Organization website URL. |
| `issuer?` | `undefined \| string` | Protocol issuer URL. Federation consumers additionally bind it to the Entity Identifier. |
| `authorization_endpoint?` | `undefined \| string` | HTTPS endpoint for authorization requests; no fragment is allowed. |
| `token_endpoint?` | `undefined \| string` | HTTPS token endpoint; required in effective metadata unless only implicit is supported. |
| `userinfo_endpoint?` | `undefined \| string` | HTTPS OpenID Connect UserInfo endpoint. |
| `jwks_uri?` | `undefined \| string` | HTTPS URL for public protocol keys, without a fragment. |
| `jwks?` | `undefined \| { [key: string]: unknown; keys: Array<JWK>; }` | JSON Web Key Set. The owning API determines whether these are Federation Entity Keys or protocol keys. |
| `registration_endpoint?` | `undefined \| string` | HTTPS dynamic client registration endpoint. |
| `scopes_supported?` | `undefined \| Array<string>` | Supported OAuth scopes. |
| `response_types_supported?` | `undefined \| Array<string>` | Supported OAuth response types; required for the normal effective AS profile. |
| `response_modes_supported?` | `undefined \| Array<string>` | Supported authorization response modes. |
| `grant_types_supported?` | `undefined \| Array<string>` | Supported OAuth grant types; omitted values use the protocol's default when evaluating conditional requirements. |
| `acr_values_supported?` | `undefined \| Array<string>` | Supported authentication context class reference values. |
| `subject_types_supported?` | `undefined \| ("public" \| "pairwise")[] & string[]` | Supported OpenID Connect subject identifier types. |
| `id_token_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted id token signing algorithms. Parsing applies this field's protocol restrictions. |
| `id_token_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted id token encryption algorithms. Parsing applies this field's protocol restrictions. |
| `id_token_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted id token encryption content-encryption methods. |
| `userinfo_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted userinfo signing algorithms. Parsing applies this field's protocol restrictions. |
| `userinfo_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted userinfo encryption algorithms. Parsing applies this field's protocol restrictions. |
| `userinfo_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted userinfo encryption content-encryption methods. |
| `request_object_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted request object signing algorithms. Parsing applies this field's protocol restrictions. |
| `request_object_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted request object encryption algorithms. Parsing applies this field's protocol restrictions. |
| `request_object_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted request object encryption content-encryption methods. |
| `token_endpoint_auth_methods_supported?` | `undefined \| Array<string>` | Supported authentication methods for token endpoint. |
| `token_endpoint_auth_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted token endpoint auth signing algorithms. Parsing applies this field's protocol restrictions. |
| `display_values_supported?` | `undefined \| Array<string>` | Supported OpenID Connect display modes. |
| `claim_types_supported?` | `undefined \| Array<string>` | Supported OpenID Connect claim representations. |
| `claims_supported?` | `undefined \| Array<string>` | Supported claim names. |
| `service_documentation?` | `undefined \| string` | URL for documentation of this authorization server. |
| `claims_locales_supported?` | `undefined \| Array<string>` | Supported languages for returned claims. |
| `ui_locales_supported?` | `undefined \| Array<string>` | Supported languages for the user interface. |
| `claims_parameter_supported?` | `undefined \| boolean` | Whether the OpenID Connect claims request parameter is supported. |
| `request_parameter_supported?` | `undefined \| boolean` | Whether a Request Object can be sent using the request parameter. |
| `request_uri_parameter_supported?` | `undefined \| boolean` | Whether Request Objects can be referenced using request_uri. |
| `require_request_uri_registration?` | `undefined \| boolean` | Whether Request Object URIs must be registered in advance. |
| `op_policy_uri?` | `undefined \| string` | URL for the provider's privacy policy. |
| `op_tos_uri?` | `undefined \| string` | URL for the provider's terms of service. |
| `end_session_endpoint?` | `undefined \| string` | HTTPS endpoint for initiating logout. |
| `frontchannel_logout_supported?` | `undefined \| boolean` | Whether front-channel logout is supported. |
| `frontchannel_logout_session_supported?` | `undefined \| boolean` | Whether front-channel logout supports session identifiers. |
| `backchannel_logout_supported?` | `undefined \| boolean` | Whether back-channel logout is supported. |
| `backchannel_logout_session_supported?` | `undefined \| boolean` | Whether back-channel logout supports session identifiers. |
| `backchannel_token_delivery_modes_supported?` | `undefined \| string[] & ("push" \| "poll" \| "ping")[]` | Supported CIBA delivery modes: poll, ping, or push. |
| `backchannel_authentication_endpoint?` | `undefined \| string` | HTTPS endpoint for CIBA authentication requests. |
| `backchannel_user_code_parameter_supported?` | `undefined \| boolean` | Whether CIBA requests support the user_code parameter. |
| `client_attestation_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted client attestation signing algorithms. Parsing applies this field's protocol restrictions. |
| `client_attestation_pop_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted client attestation pop signing algorithms. Parsing applies this field's protocol restrictions. |
| `challenge_endpoint?` | `undefined \| string` | Client-attestation challenge endpoint URL; this schema checks URL syntax, not endpoint trust. |
| `revocation_endpoint?` | `undefined \| string` | HTTPS endpoint for token revocation. |
| `revocation_endpoint_auth_methods_supported?` | `undefined \| Array<string>` | Supported authentication methods for revocation endpoint. |
| `revocation_endpoint_auth_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted revocation endpoint auth signing algorithms. Parsing applies this field's protocol restrictions. |
| `introspection_endpoint?` | `undefined \| string` | HTTPS endpoint for token introspection. |
| `introspection_endpoint_auth_methods_supported?` | `undefined \| Array<string>` | Supported authentication methods for introspection endpoint. |
| `introspection_endpoint_auth_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted introspection endpoint auth signing algorithms. Parsing applies this field's protocol restrictions. |
| `introspection_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted introspection signing algorithms. Parsing applies this field's protocol restrictions. |
| `introspection_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted introspection encryption algorithms. Parsing applies this field's protocol restrictions. |
| `introspection_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted introspection encryption content-encryption methods. |
| `nfv_token_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted nfv token signing algorithms. Parsing applies this field's protocol restrictions. |
| `nfv_token_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted nfv token encryption algorithms. Parsing applies this field's protocol restrictions. |
| `nfv_token_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted nfv token encryption content-encryption methods. |
| `code_challenge_methods_supported?` | `undefined \| Array<string>` | Supported PKCE code challenge methods. |
| `device_authorization_endpoint?` | `undefined \| string` | HTTPS device authorization endpoint, without a fragment. |
| `pushed_authorization_request_endpoint?` | `undefined \| string` | HTTPS Pushed Authorization Request endpoint, without a fragment. |
| `require_pushed_authorization_requests?` | `undefined \| boolean` | Whether clients must use PAR. |
| `require_signed_request_object?` | `undefined \| boolean` | Whether Request Objects must be signed. |
| `dpop_signing_alg_values_supported?` | `undefined \| Array<string>` | Supported asymmetric DPoP signing algorithms; none and symmetric HMAC algorithms are rejected. |
| `authorization_response_iss_parameter_supported?` | `undefined \| boolean` | Whether authorization responses support an issuer identifier parameter. |
| `authorization_details_types_supported?` | `undefined \| Array<string>` | Supported authorization_details type values. |
| `protected_resources?` | `undefined \| Array<string>` | Protected-resource identifiers served by this authorization server. |
| `tls_client_certificate_bound_access_tokens?` | `undefined \| boolean` | Whether this participant supports certificate-bound access tokens. |
| `mtls_endpoint_aliases?` | `undefined \| { [key: string]: unknown; token_endpoint?: undefined \| string; revocation_endpoint?: undefined \| string; introspection_endpoint?: undefined \| string; device_authorization_endpoint?: undefined \| string; pushed_authorization_request_endpoint?: undefined \| string; userinfo_endpoint?: undefined \| string; backchannel_authentication_endpoint?: undefined \| string; }` | Optional HTTPS endpoint aliases for mutual-TLS access. Unknown extension aliases are preserved. |
| `signed_metadata?` | `undefined \| string` | Signed metadata JWT preserved as metadata; parsing does not verify its signature. |

## `OpenIDRelyingPartyMetadata`

[Source](../../../packages/oidc/src/schemas/metadata.ts#L541)

Effective OIDC relying-party metadata type. Required relationships, including redirect-based flows, are enforced at runtime even where fields remain optional in TypeScript. Use the matching role's parseMetadata method. Registration-response credentials are rejected in publication metadata; unknown extensions are preserved.

<details>
<summary>Type declaration</summary>

```typescript signature
type OpenIDRelyingPartyMetadata = {
	[key: string]: unknown;
	jwks_uri?: undefined | string;
	jwks?: undefined | { [key: string]: unknown; keys: Array<JWK>; };
	sector_identifier_uri?: undefined | string;
	request_uris?: undefined | Array<string>;
	subject_type?: undefined | "public" | "pairwise";
	id_token_signed_response_alg?: undefined | string;
	id_token_encrypted_response_alg?: undefined | string;
	id_token_encrypted_response_enc?: undefined | string;
	userinfo_signed_response_alg?: undefined | string;
	userinfo_encrypted_response_alg?: undefined | string;
	userinfo_encrypted_response_enc?: undefined | string;
	request_object_signing_alg?: undefined | string;
	request_object_encryption_alg?: undefined | string;
	request_object_encryption_enc?: undefined | string;
	token_endpoint_auth_method?: undefined | string;
	token_endpoint_auth_signing_alg?: undefined | string;
	default_max_age?: undefined | number;
	require_auth_time?: undefined | boolean;
	default_acr_values?: undefined | Array<string>;
	initiate_login_uri?: undefined | string;
	post_logout_redirect_uris?: undefined | Array<string>;
	backchannel_token_delivery_mode?: undefined | "push" | "poll" | "ping";
	backchannel_client_notification_endpoint?: undefined | string;
	backchannel_authentication_request_signing_alg?: undefined | string;
	backchannel_user_code_parameter?: undefined | boolean;
	client_registration_types?: undefined | Array<string>;
	signed_jwks_uri?: undefined | string;
	organization_identifier?: undefined | string;
	scope?: undefined | string;
	organization_name?: undefined | string;
	display_name?: undefined | string;
	description?: undefined | string;
	keywords?: undefined | Array<string>;
	contacts?: undefined | Array<string>;
	logo_uri?: undefined | string;
	policy_uri?: undefined | string;
	information_uri?: undefined | string;
	organization_uri?: undefined | string;
	frontchannel_logout_uri?: undefined | string;
	frontchannel_logout_session_required?: undefined | boolean;
	backchannel_logout_uri?: undefined | string;
	backchannel_logout_session_required?: undefined | boolean;
	redirect_uris?: undefined | Array<string>;
	response_types?: undefined | Array<string>;
	grant_types?: undefined | Array<string>;
	application_type?: undefined | "web" | "native";
	client_name?: undefined | string;
	client_uri?: undefined | string;
	tos_uri?: undefined | string;
	subject_types_supported?: undefined | Array<string>;
	id_token_signing_alg_values_supported?: undefined | Array<string>;
	id_token_encryption_alg_values_supported?: undefined | Array<string>;
	id_token_encryption_enc_values_supported?: undefined | Array<string>;
	userinfo_signing_alg_values_supported?: undefined | Array<string>;
	userinfo_encryption_alg_values_supported?: undefined | Array<string>;
	userinfo_encryption_enc_values_supported?: undefined | Array<string>;
	request_object_signing_alg_values_supported?: undefined | Array<string>;
	request_object_encryption_alg_values_supported?: undefined | Array<string>;
	request_object_encryption_enc_values_supported?: undefined | Array<string>;
	token_endpoint_auth_methods_supported?: undefined | Array<string>;
	token_endpoint_auth_signing_alg_values_supported?: undefined | Array<string>;
	backchannel_authentication_request_signing_alg_values_supported?: undefined | Array<string>;
	authorization_signing_alg_values_supported?: undefined | Array<string>;
	authorization_encryption_alg_values_supported?: undefined | Array<string>;
	authorization_encryption_enc_values_supported?: undefined | Array<string>;
	introspection_signing_alg_values_supported?: undefined | Array<string>;
	introspection_encryption_alg_values_supported?: undefined | Array<string>;
	introspection_encryption_enc_values_supported?: undefined | Array<string>;
	software_id?: undefined | string;
	software_version?: undefined | string;
	software_statement?: undefined | string;
	claims_redirect_uris?: undefined | Array<string>;
	nfv_token_signed_response_alg?: undefined | string;
	nfv_token_encrypted_response_alg?: undefined | string;
	nfv_token_encrypted_response_enc?: undefined | string;
	tls_client_certificate_bound_access_tokens?: undefined | boolean;
	tls_client_auth_subject_dn?: undefined | string;
	tls_client_auth_san_dns?: undefined | string;
	tls_client_auth_san_uri?: undefined | string;
	tls_client_auth_san_ip?: undefined | string;
	tls_client_auth_san_email?: undefined | string;
	require_signed_request_object?: undefined | boolean;
	require_pushed_authorization_requests?: undefined | boolean;
	use_mtls_endpoint_aliases?: undefined | boolean;
	authorization_details_types?: undefined | Array<string>;
	dpop_bound_access_tokens?: undefined | boolean;
	introspection_signed_response_alg?: undefined | string;
	introspection_encrypted_response_alg?: undefined | string;
	introspection_encrypted_response_enc?: undefined | string;
	authorization_signed_response_alg?: undefined | string;
	authorization_encrypted_response_alg?: undefined | string;
	authorization_encrypted_response_enc?: undefined | string;
};
```

</details>

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `jwks_uri?` | `undefined \| string` | HTTPS URL for public protocol keys, without a fragment. |
| `jwks?` | `undefined \| { [key: string]: unknown; keys: Array<JWK>; }` | JSON Web Key Set. The owning API determines whether these are Federation Entity Keys or protocol keys. |
| `sector_identifier_uri?` | `undefined \| string` | HTTPS URL for the client's sector identifier document. Parsing does not fetch the document. |
| `request_uris?` | `undefined \| Array<string>` | Registered Request Object URLs. |
| `subject_type?` | `undefined \| "public" \| "pairwise"` | Selected OIDC subject identifier type: public or pairwise; it must belong to any supplied subject_types_supported choices. |
| `id_token_signed_response_alg?` | `undefined \| string` | Selected signing algorithm for id token responses. |
| `id_token_encrypted_response_alg?` | `undefined \| string` | Selected key-management algorithm for id token response encryption. |
| `id_token_encrypted_response_enc?` | `undefined \| string` | Selected content-encryption method for id token responses. |
| `userinfo_signed_response_alg?` | `undefined \| string` | Selected signing algorithm for userinfo responses. |
| `userinfo_encrypted_response_alg?` | `undefined \| string` | Selected key-management algorithm for userinfo response encryption. |
| `userinfo_encrypted_response_enc?` | `undefined \| string` | Selected content-encryption method for userinfo responses. |
| `request_object_signing_alg?` | `undefined \| string` | Selected Request Object signing algorithm. |
| `request_object_encryption_alg?` | `undefined \| string` | Selected Request Object key-management algorithm. |
| `request_object_encryption_enc?` | `undefined \| string` | Selected Request Object content-encryption method. |
| `token_endpoint_auth_method?` | `undefined \| string` | Selected token endpoint authentication method; extension string values are preserved. |
| `token_endpoint_auth_signing_alg?` | `undefined \| string` | Signing algorithm for JWT client authentication; none is rejected. |
| `default_max_age?` | `undefined \| number` | Default authentication age in nonnegative integer seconds. |
| `require_auth_time?` | `undefined \| boolean` | Whether an authentication time claim is required by the client. |
| `default_acr_values?` | `undefined \| Array<string>` | Default requested authentication context class reference values. |
| `initiate_login_uri?` | `undefined \| string` | HTTPS URL at which the client accepts third-party initiated login. |
| `post_logout_redirect_uris?` | `undefined \| Array<string>` | Registered post-logout redirect URLs. |
| `backchannel_token_delivery_mode?` | `undefined \| "push" \| "poll" \| "ping"` | Selected CIBA mode: poll, ping, or push. Effective metadata enforces its grant and notification dependencies. |
| `backchannel_client_notification_endpoint?` | `undefined \| string` | HTTPS client notification endpoint, required for effective CIBA ping or push delivery. |
| `backchannel_authentication_request_signing_alg?` | `undefined \| string` | Signing algorithm for CIBA authentication requests. |
| `backchannel_user_code_parameter?` | `undefined \| boolean` | Whether the CIBA client uses the user_code parameter. |
| `client_registration_types?` | `undefined \| Array<string>` | Supported client registration modes. Additional string values remain permitted. |
| `signed_jwks_uri?` | `undefined \| string` | HTTPS URL for a signed protocol JWK Set, without a fragment. |
| `organization_identifier?` | `undefined \| string` | Organization identifier supplied as informational metadata. |
| `scope?` | `undefined \| string` | Space-separated OAuth scopes requested or registered for this client. |
| `organization_name?` | `undefined \| string` | Human-readable organization name. |
| `display_name?` | `undefined \| string` | Human-readable display name. |
| `description?` | `undefined \| string` | Human-readable description. |
| `keywords?` | `undefined \| Array<string>` | Informational search keywords; a supplied list must be nonempty. |
| `contacts?` | `undefined \| Array<string>` | Contact addresses; a supplied list must be nonempty. |
| `logo_uri?` | `undefined \| string` | Logo URL for the entity or Trust Mark described by this metadata. |
| `policy_uri?` | `undefined \| string` | Policy information URL. |
| `information_uri?` | `undefined \| string` | Additional entity information URL. |
| `organization_uri?` | `undefined \| string` | Organization website URL. |
| `frontchannel_logout_uri?` | `undefined \| string` | HTTPS front-channel logout URI, without a fragment. |
| `frontchannel_logout_session_required?` | `undefined \| boolean` | Whether the client requires session information for front-channel logout. |
| `backchannel_logout_uri?` | `undefined \| string` | HTTPS back-channel logout URI, without a fragment. |
| `backchannel_logout_session_required?` | `undefined \| boolean` | Whether the client requires session information for back-channel logout. |
| `redirect_uris?` | `undefined \| Array<string>` | Registered redirect URLs. The effective parser enforces flow-dependent presence and redirect security rules. |
| `response_types?` | `undefined \| Array<string>` | Client response types; effective metadata checks consistency with the grant types. |
| `grant_types?` | `undefined \| Array<string>` | Client grant types; conditional redirect, response-type, and CIBA requirements are checked by the parser. |
| `application_type?` | `undefined \| "web" \| "native"` | OIDC application type: web or native. Redirect requirements depend on this value and the flow. |
| `client_name?` | `undefined \| string` | Human-readable client name. |
| `client_uri?` | `undefined \| string` | Client information URL. |
| `tos_uri?` | `undefined \| string` | Client terms-of-service URL. |
| `subject_types_supported?` | `undefined \| Array<string>` | Supported OpenID Connect subject identifier types. |
| `id_token_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted id token signing algorithms. Parsing applies this field's protocol restrictions. |
| `id_token_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted id token encryption algorithms. Parsing applies this field's protocol restrictions. |
| `id_token_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted id token encryption content-encryption methods. |
| `userinfo_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted userinfo signing algorithms. Parsing applies this field's protocol restrictions. |
| `userinfo_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted userinfo encryption algorithms. Parsing applies this field's protocol restrictions. |
| `userinfo_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted userinfo encryption content-encryption methods. |
| `request_object_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted request object signing algorithms. Parsing applies this field's protocol restrictions. |
| `request_object_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted request object encryption algorithms. Parsing applies this field's protocol restrictions. |
| `request_object_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted request object encryption content-encryption methods. |
| `token_endpoint_auth_methods_supported?` | `undefined \| Array<string>` | Supported authentication methods for token endpoint. |
| `token_endpoint_auth_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted token endpoint auth signing algorithms. Parsing applies this field's protocol restrictions. |
| `backchannel_authentication_request_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted backchannel authentication request signing algorithms. Parsing applies this field's protocol restrictions. |
| `authorization_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted authorization signing algorithms. Parsing applies this field's protocol restrictions. |
| `authorization_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted authorization encryption algorithms. Parsing applies this field's protocol restrictions. |
| `authorization_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted authorization encryption content-encryption methods. |
| `introspection_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted introspection signing algorithms. Parsing applies this field's protocol restrictions. |
| `introspection_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted introspection encryption algorithms. Parsing applies this field's protocol restrictions. |
| `introspection_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted introspection encryption content-encryption methods. |
| `software_id?` | `undefined \| string` | Client software identifier. |
| `software_version?` | `undefined \| string` | Client software version. |
| `software_statement?` | `undefined \| string` | Software statement JWT preserved as metadata; parsing does not authenticate its signer. |
| `claims_redirect_uris?` | `undefined \| Array<string>` | Client URLs used for claims-redirection workflows. |
| `nfv_token_signed_response_alg?` | `undefined \| string` | Selected signing algorithm for nfv token responses. |
| `nfv_token_encrypted_response_alg?` | `undefined \| string` | Selected key-management algorithm for nfv token response encryption. |
| `nfv_token_encrypted_response_enc?` | `undefined \| string` | Selected content-encryption method for nfv token responses. |
| `tls_client_certificate_bound_access_tokens?` | `undefined \| boolean` | Whether this participant supports certificate-bound access tokens. |
| `tls_client_auth_subject_dn?` | `undefined \| string` | Expected certificate subject distinguished name. Effective tls_client_auth metadata requires exactly one certificate selector. |
| `tls_client_auth_san_dns?` | `undefined \| string` | Expected DNS subjectAltName. Effective tls_client_auth metadata requires exactly one certificate selector. |
| `tls_client_auth_san_uri?` | `undefined \| string` | Expected URI subjectAltName. Effective tls_client_auth metadata requires exactly one certificate selector. |
| `tls_client_auth_san_ip?` | `undefined \| string` | Expected IP subjectAltName. Effective tls_client_auth metadata requires exactly one certificate selector. |
| `tls_client_auth_san_email?` | `undefined \| string` | Expected email subjectAltName. Effective tls_client_auth metadata requires exactly one certificate selector. |
| `require_signed_request_object?` | `undefined \| boolean` | Whether Request Objects must be signed. |
| `require_pushed_authorization_requests?` | `undefined \| boolean` | Whether clients must use PAR. |
| `use_mtls_endpoint_aliases?` | `undefined \| boolean` | Whether the client requests the server's mutual-TLS endpoint aliases. |
| `authorization_details_types?` | `undefined \| Array<string>` | Authorization-details types requested by the client. |
| `dpop_bound_access_tokens?` | `undefined \| boolean` | Whether the client requests DPoP-bound access tokens. |
| `introspection_signed_response_alg?` | `undefined \| string` | Selected signing algorithm for introspection responses. |
| `introspection_encrypted_response_alg?` | `undefined \| string` | Selected key-management algorithm for introspection response encryption. |
| `introspection_encrypted_response_enc?` | `undefined \| string` | Selected content-encryption method for introspection responses. |
| `authorization_signed_response_alg?` | `undefined \| string` | Selected signing algorithm for authorization responses. |
| `authorization_encrypted_response_alg?` | `undefined \| string` | Selected key-management algorithm for authorization response encryption. |
| `authorization_encrypted_response_enc?` | `undefined \| string` | Selected content-encryption method for authorization responses. |

## `OpenIDRelyingPartyPublicationMetadata`

[Source](../../../packages/oidc/src/schemas/metadata.ts#L683)

Publication metadata type for a client EC or Superior statement whose missing fields may be completed later. The matching role's parsePublicationMetadata checks supplied fields and applicable consistency rules, while deferring effective requirements. Registration-response credential fields cannot be published.

<details>
<summary>Type declaration</summary>

```typescript signature
type OpenIDRelyingPartyPublicationMetadata = {
	[key: string]: unknown;
	jwks_uri?: undefined | string;
	jwks?: undefined | { [key: string]: unknown; keys: Array<JWK>; };
	sector_identifier_uri?: undefined | string;
	request_uris?: undefined | Array<string>;
	subject_type?: undefined | "public" | "pairwise";
	id_token_signed_response_alg?: undefined | string;
	id_token_encrypted_response_alg?: undefined | string;
	id_token_encrypted_response_enc?: undefined | string;
	userinfo_signed_response_alg?: undefined | string;
	userinfo_encrypted_response_alg?: undefined | string;
	userinfo_encrypted_response_enc?: undefined | string;
	request_object_signing_alg?: undefined | string;
	request_object_encryption_alg?: undefined | string;
	request_object_encryption_enc?: undefined | string;
	token_endpoint_auth_method?: undefined | string;
	token_endpoint_auth_signing_alg?: undefined | string;
	default_max_age?: undefined | number;
	require_auth_time?: undefined | boolean;
	default_acr_values?: undefined | Array<string>;
	initiate_login_uri?: undefined | string;
	post_logout_redirect_uris?: undefined | Array<string>;
	backchannel_token_delivery_mode?: undefined | "push" | "poll" | "ping";
	backchannel_client_notification_endpoint?: undefined | string;
	backchannel_authentication_request_signing_alg?: undefined | string;
	backchannel_user_code_parameter?: undefined | boolean;
	client_registration_types?: undefined | Array<string>;
	signed_jwks_uri?: undefined | string;
	organization_identifier?: undefined | string;
	scope?: undefined | string;
	organization_name?: undefined | string;
	display_name?: undefined | string;
	description?: undefined | string;
	keywords?: undefined | Array<string>;
	contacts?: undefined | Array<string>;
	logo_uri?: undefined | string;
	policy_uri?: undefined | string;
	information_uri?: undefined | string;
	organization_uri?: undefined | string;
	frontchannel_logout_uri?: undefined | string;
	frontchannel_logout_session_required?: undefined | boolean;
	backchannel_logout_uri?: undefined | string;
	backchannel_logout_session_required?: undefined | boolean;
	redirect_uris?: undefined | Array<string>;
	response_types?: undefined | Array<string>;
	grant_types?: undefined | Array<string>;
	application_type?: undefined | "web" | "native";
	client_name?: undefined | string;
	client_uri?: undefined | string;
	tos_uri?: undefined | string;
	subject_types_supported?: undefined | Array<string>;
	id_token_signing_alg_values_supported?: undefined | Array<string>;
	id_token_encryption_alg_values_supported?: undefined | Array<string>;
	id_token_encryption_enc_values_supported?: undefined | Array<string>;
	userinfo_signing_alg_values_supported?: undefined | Array<string>;
	userinfo_encryption_alg_values_supported?: undefined | Array<string>;
	userinfo_encryption_enc_values_supported?: undefined | Array<string>;
	request_object_signing_alg_values_supported?: undefined | Array<string>;
	request_object_encryption_alg_values_supported?: undefined | Array<string>;
	request_object_encryption_enc_values_supported?: undefined | Array<string>;
	token_endpoint_auth_methods_supported?: undefined | Array<string>;
	token_endpoint_auth_signing_alg_values_supported?: undefined | Array<string>;
	backchannel_authentication_request_signing_alg_values_supported?: undefined | Array<string>;
	authorization_signing_alg_values_supported?: undefined | Array<string>;
	authorization_encryption_alg_values_supported?: undefined | Array<string>;
	authorization_encryption_enc_values_supported?: undefined | Array<string>;
	introspection_signing_alg_values_supported?: undefined | Array<string>;
	introspection_encryption_alg_values_supported?: undefined | Array<string>;
	introspection_encryption_enc_values_supported?: undefined | Array<string>;
	software_id?: undefined | string;
	software_version?: undefined | string;
	software_statement?: undefined | string;
	claims_redirect_uris?: undefined | Array<string>;
	nfv_token_signed_response_alg?: undefined | string;
	nfv_token_encrypted_response_alg?: undefined | string;
	nfv_token_encrypted_response_enc?: undefined | string;
	tls_client_certificate_bound_access_tokens?: undefined | boolean;
	tls_client_auth_subject_dn?: undefined | string;
	tls_client_auth_san_dns?: undefined | string;
	tls_client_auth_san_uri?: undefined | string;
	tls_client_auth_san_ip?: undefined | string;
	tls_client_auth_san_email?: undefined | string;
	require_signed_request_object?: undefined | boolean;
	require_pushed_authorization_requests?: undefined | boolean;
	use_mtls_endpoint_aliases?: undefined | boolean;
	authorization_details_types?: undefined | Array<string>;
	dpop_bound_access_tokens?: undefined | boolean;
	introspection_signed_response_alg?: undefined | string;
	introspection_encrypted_response_alg?: undefined | string;
	introspection_encrypted_response_enc?: undefined | string;
	authorization_signed_response_alg?: undefined | string;
	authorization_encrypted_response_alg?: undefined | string;
	authorization_encrypted_response_enc?: undefined | string;
};
```

</details>

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `jwks_uri?` | `undefined \| string` | HTTPS URL for public protocol keys, without a fragment. |
| `jwks?` | `undefined \| { [key: string]: unknown; keys: Array<JWK>; }` | JSON Web Key Set. The owning API determines whether these are Federation Entity Keys or protocol keys. |
| `sector_identifier_uri?` | `undefined \| string` | HTTPS URL for the client's sector identifier document. Parsing does not fetch the document. |
| `request_uris?` | `undefined \| Array<string>` | Registered Request Object URLs. |
| `subject_type?` | `undefined \| "public" \| "pairwise"` | Selected OIDC subject identifier type: public or pairwise; it must belong to any supplied subject_types_supported choices. |
| `id_token_signed_response_alg?` | `undefined \| string` | Selected signing algorithm for id token responses. |
| `id_token_encrypted_response_alg?` | `undefined \| string` | Selected key-management algorithm for id token response encryption. |
| `id_token_encrypted_response_enc?` | `undefined \| string` | Selected content-encryption method for id token responses. |
| `userinfo_signed_response_alg?` | `undefined \| string` | Selected signing algorithm for userinfo responses. |
| `userinfo_encrypted_response_alg?` | `undefined \| string` | Selected key-management algorithm for userinfo response encryption. |
| `userinfo_encrypted_response_enc?` | `undefined \| string` | Selected content-encryption method for userinfo responses. |
| `request_object_signing_alg?` | `undefined \| string` | Selected Request Object signing algorithm. |
| `request_object_encryption_alg?` | `undefined \| string` | Selected Request Object key-management algorithm. |
| `request_object_encryption_enc?` | `undefined \| string` | Selected Request Object content-encryption method. |
| `token_endpoint_auth_method?` | `undefined \| string` | Selected token endpoint authentication method; extension string values are preserved. |
| `token_endpoint_auth_signing_alg?` | `undefined \| string` | Signing algorithm for JWT client authentication; none is rejected. |
| `default_max_age?` | `undefined \| number` | Default authentication age in nonnegative integer seconds. |
| `require_auth_time?` | `undefined \| boolean` | Whether an authentication time claim is required by the client. |
| `default_acr_values?` | `undefined \| Array<string>` | Default requested authentication context class reference values. |
| `initiate_login_uri?` | `undefined \| string` | HTTPS URL at which the client accepts third-party initiated login. |
| `post_logout_redirect_uris?` | `undefined \| Array<string>` | Registered post-logout redirect URLs. |
| `backchannel_token_delivery_mode?` | `undefined \| "push" \| "poll" \| "ping"` | Selected CIBA mode: poll, ping, or push. Effective metadata enforces its grant and notification dependencies. |
| `backchannel_client_notification_endpoint?` | `undefined \| string` | HTTPS client notification endpoint, required for effective CIBA ping or push delivery. |
| `backchannel_authentication_request_signing_alg?` | `undefined \| string` | Signing algorithm for CIBA authentication requests. |
| `backchannel_user_code_parameter?` | `undefined \| boolean` | Whether the CIBA client uses the user_code parameter. |
| `client_registration_types?` | `undefined \| Array<string>` | Supported client registration modes. Additional string values remain permitted. |
| `signed_jwks_uri?` | `undefined \| string` | HTTPS URL for a signed protocol JWK Set, without a fragment. |
| `organization_identifier?` | `undefined \| string` | Organization identifier supplied as informational metadata. |
| `scope?` | `undefined \| string` | Space-separated OAuth scopes requested or registered for this client. |
| `organization_name?` | `undefined \| string` | Human-readable organization name. |
| `display_name?` | `undefined \| string` | Human-readable display name. |
| `description?` | `undefined \| string` | Human-readable description. |
| `keywords?` | `undefined \| Array<string>` | Informational search keywords; a supplied list must be nonempty. |
| `contacts?` | `undefined \| Array<string>` | Contact addresses; a supplied list must be nonempty. |
| `logo_uri?` | `undefined \| string` | Logo URL for the entity or Trust Mark described by this metadata. |
| `policy_uri?` | `undefined \| string` | Policy information URL. |
| `information_uri?` | `undefined \| string` | Additional entity information URL. |
| `organization_uri?` | `undefined \| string` | Organization website URL. |
| `frontchannel_logout_uri?` | `undefined \| string` | HTTPS front-channel logout URI, without a fragment. |
| `frontchannel_logout_session_required?` | `undefined \| boolean` | Whether the client requires session information for front-channel logout. |
| `backchannel_logout_uri?` | `undefined \| string` | HTTPS back-channel logout URI, without a fragment. |
| `backchannel_logout_session_required?` | `undefined \| boolean` | Whether the client requires session information for back-channel logout. |
| `redirect_uris?` | `undefined \| Array<string>` | Registered redirect URLs. The effective parser enforces flow-dependent presence and redirect security rules. |
| `response_types?` | `undefined \| Array<string>` | Client response types; effective metadata checks consistency with the grant types. |
| `grant_types?` | `undefined \| Array<string>` | Client grant types; conditional redirect, response-type, and CIBA requirements are checked by the parser. |
| `application_type?` | `undefined \| "web" \| "native"` | OIDC application type: web or native. Redirect requirements depend on this value and the flow. |
| `client_name?` | `undefined \| string` | Human-readable client name. |
| `client_uri?` | `undefined \| string` | Client information URL. |
| `tos_uri?` | `undefined \| string` | Client terms-of-service URL. |
| `subject_types_supported?` | `undefined \| Array<string>` | Supported OpenID Connect subject identifier types. |
| `id_token_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted id token signing algorithms. Parsing applies this field's protocol restrictions. |
| `id_token_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted id token encryption algorithms. Parsing applies this field's protocol restrictions. |
| `id_token_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted id token encryption content-encryption methods. |
| `userinfo_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted userinfo signing algorithms. Parsing applies this field's protocol restrictions. |
| `userinfo_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted userinfo encryption algorithms. Parsing applies this field's protocol restrictions. |
| `userinfo_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted userinfo encryption content-encryption methods. |
| `request_object_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted request object signing algorithms. Parsing applies this field's protocol restrictions. |
| `request_object_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted request object encryption algorithms. Parsing applies this field's protocol restrictions. |
| `request_object_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted request object encryption content-encryption methods. |
| `token_endpoint_auth_methods_supported?` | `undefined \| Array<string>` | Supported authentication methods for token endpoint. |
| `token_endpoint_auth_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted token endpoint auth signing algorithms. Parsing applies this field's protocol restrictions. |
| `backchannel_authentication_request_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted backchannel authentication request signing algorithms. Parsing applies this field's protocol restrictions. |
| `authorization_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted authorization signing algorithms. Parsing applies this field's protocol restrictions. |
| `authorization_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted authorization encryption algorithms. Parsing applies this field's protocol restrictions. |
| `authorization_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted authorization encryption content-encryption methods. |
| `introspection_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted introspection signing algorithms. Parsing applies this field's protocol restrictions. |
| `introspection_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted introspection encryption algorithms. Parsing applies this field's protocol restrictions. |
| `introspection_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted introspection encryption content-encryption methods. |
| `software_id?` | `undefined \| string` | Client software identifier. |
| `software_version?` | `undefined \| string` | Client software version. |
| `software_statement?` | `undefined \| string` | Software statement JWT preserved as metadata; parsing does not authenticate its signer. |
| `claims_redirect_uris?` | `undefined \| Array<string>` | Client URLs used for claims-redirection workflows. |
| `nfv_token_signed_response_alg?` | `undefined \| string` | Selected signing algorithm for nfv token responses. |
| `nfv_token_encrypted_response_alg?` | `undefined \| string` | Selected key-management algorithm for nfv token response encryption. |
| `nfv_token_encrypted_response_enc?` | `undefined \| string` | Selected content-encryption method for nfv token responses. |
| `tls_client_certificate_bound_access_tokens?` | `undefined \| boolean` | Whether this participant supports certificate-bound access tokens. |
| `tls_client_auth_subject_dn?` | `undefined \| string` | Expected certificate subject distinguished name. Effective tls_client_auth metadata requires exactly one certificate selector. |
| `tls_client_auth_san_dns?` | `undefined \| string` | Expected DNS subjectAltName. Effective tls_client_auth metadata requires exactly one certificate selector. |
| `tls_client_auth_san_uri?` | `undefined \| string` | Expected URI subjectAltName. Effective tls_client_auth metadata requires exactly one certificate selector. |
| `tls_client_auth_san_ip?` | `undefined \| string` | Expected IP subjectAltName. Effective tls_client_auth metadata requires exactly one certificate selector. |
| `tls_client_auth_san_email?` | `undefined \| string` | Expected email subjectAltName. Effective tls_client_auth metadata requires exactly one certificate selector. |
| `require_signed_request_object?` | `undefined \| boolean` | Whether Request Objects must be signed. |
| `require_pushed_authorization_requests?` | `undefined \| boolean` | Whether clients must use PAR. |
| `use_mtls_endpoint_aliases?` | `undefined \| boolean` | Whether the client requests the server's mutual-TLS endpoint aliases. |
| `authorization_details_types?` | `undefined \| Array<string>` | Authorization-details types requested by the client. |
| `dpop_bound_access_tokens?` | `undefined \| boolean` | Whether the client requests DPoP-bound access tokens. |
| `introspection_signed_response_alg?` | `undefined \| string` | Selected signing algorithm for introspection responses. |
| `introspection_encrypted_response_alg?` | `undefined \| string` | Selected key-management algorithm for introspection response encryption. |
| `introspection_encrypted_response_enc?` | `undefined \| string` | Selected content-encryption method for introspection responses. |
| `authorization_signed_response_alg?` | `undefined \| string` | Selected signing algorithm for authorization responses. |
| `authorization_encrypted_response_alg?` | `undefined \| string` | Selected key-management algorithm for authorization response encryption. |
| `authorization_encrypted_response_enc?` | `undefined \| string` | Selected content-encryption method for authorization responses. |

## `OpenIDRelyingPartyRegistrationResponseMetadata`

[Source](../../../packages/oidc/src/schemas/metadata.ts#L543)

Client metadata carried in a verified Explicit Registration response. client_id is required; optional secrets and management credentials belong in this block. The OIDC response rejects plural RP Metadata Choices inputs after the protocol engine selects singular values. Shape validity alone does not authenticate a response or enforce read-only token permissions.

<details>
<summary>Type declaration</summary>

```typescript signature
type OpenIDRelyingPartyRegistrationResponseMetadata = {
	[key: string]: unknown;
	client_id: string;
	client_secret?: undefined | string;
	client_id_issued_at?: undefined | number;
	client_secret_expires_at?: undefined | number;
	registration_access_token?: undefined | string;
	registration_client_uri?: undefined | string;
	jwks_uri?: undefined | string;
	jwks?: undefined | { [key: string]: unknown; keys: Array<JWK>; };
	sector_identifier_uri?: undefined | string;
	request_uris?: undefined | Array<string>;
	subject_type?: undefined | "public" | "pairwise";
	id_token_signed_response_alg?: undefined | string;
	id_token_encrypted_response_alg?: undefined | string;
	id_token_encrypted_response_enc?: undefined | string;
	userinfo_signed_response_alg?: undefined | string;
	userinfo_encrypted_response_alg?: undefined | string;
	userinfo_encrypted_response_enc?: undefined | string;
	request_object_signing_alg?: undefined | string;
	request_object_encryption_alg?: undefined | string;
	request_object_encryption_enc?: undefined | string;
	token_endpoint_auth_method?: undefined | string;
	token_endpoint_auth_signing_alg?: undefined | string;
	default_max_age?: undefined | number;
	require_auth_time?: undefined | boolean;
	default_acr_values?: undefined | Array<string>;
	initiate_login_uri?: undefined | string;
	post_logout_redirect_uris?: undefined | Array<string>;
	backchannel_token_delivery_mode?: undefined | "push" | "poll" | "ping";
	backchannel_client_notification_endpoint?: undefined | string;
	backchannel_authentication_request_signing_alg?: undefined | string;
	backchannel_user_code_parameter?: undefined | boolean;
	client_registration_types?: undefined | Array<string>;
	signed_jwks_uri?: undefined | string;
	organization_identifier?: undefined | string;
	scope?: undefined | string;
	organization_name?: undefined | string;
	display_name?: undefined | string;
	description?: undefined | string;
	keywords?: undefined | Array<string>;
	contacts?: undefined | Array<string>;
	logo_uri?: undefined | string;
	policy_uri?: undefined | string;
	information_uri?: undefined | string;
	organization_uri?: undefined | string;
	frontchannel_logout_uri?: undefined | string;
	frontchannel_logout_session_required?: undefined | boolean;
	backchannel_logout_uri?: undefined | string;
	backchannel_logout_session_required?: undefined | boolean;
	redirect_uris?: undefined | Array<string>;
	response_types?: undefined | Array<string>;
	grant_types?: undefined | Array<string>;
	application_type?: undefined | "web" | "native";
	client_name?: undefined | string;
	client_uri?: undefined | string;
	tos_uri?: undefined | string;
	subject_types_supported?: undefined | Array<string>;
	id_token_signing_alg_values_supported?: undefined | Array<string>;
	id_token_encryption_alg_values_supported?: undefined | Array<string>;
	id_token_encryption_enc_values_supported?: undefined | Array<string>;
	userinfo_signing_alg_values_supported?: undefined | Array<string>;
	userinfo_encryption_alg_values_supported?: undefined | Array<string>;
	userinfo_encryption_enc_values_supported?: undefined | Array<string>;
	request_object_signing_alg_values_supported?: undefined | Array<string>;
	request_object_encryption_alg_values_supported?: undefined | Array<string>;
	request_object_encryption_enc_values_supported?: undefined | Array<string>;
	token_endpoint_auth_methods_supported?: undefined | Array<string>;
	token_endpoint_auth_signing_alg_values_supported?: undefined | Array<string>;
	backchannel_authentication_request_signing_alg_values_supported?: undefined | Array<string>;
	authorization_signing_alg_values_supported?: undefined | Array<string>;
	authorization_encryption_alg_values_supported?: undefined | Array<string>;
	authorization_encryption_enc_values_supported?: undefined | Array<string>;
	introspection_signing_alg_values_supported?: undefined | Array<string>;
	introspection_encryption_alg_values_supported?: undefined | Array<string>;
	introspection_encryption_enc_values_supported?: undefined | Array<string>;
	software_id?: undefined | string;
	software_version?: undefined | string;
	software_statement?: undefined | string;
	claims_redirect_uris?: undefined | Array<string>;
	nfv_token_signed_response_alg?: undefined | string;
	nfv_token_encrypted_response_alg?: undefined | string;
	nfv_token_encrypted_response_enc?: undefined | string;
	tls_client_certificate_bound_access_tokens?: undefined | boolean;
	tls_client_auth_subject_dn?: undefined | string;
	tls_client_auth_san_dns?: undefined | string;
	tls_client_auth_san_uri?: undefined | string;
	tls_client_auth_san_ip?: undefined | string;
	tls_client_auth_san_email?: undefined | string;
	require_signed_request_object?: undefined | boolean;
	require_pushed_authorization_requests?: undefined | boolean;
	use_mtls_endpoint_aliases?: undefined | boolean;
	authorization_details_types?: undefined | Array<string>;
	dpop_bound_access_tokens?: undefined | boolean;
	introspection_signed_response_alg?: undefined | string;
	introspection_encrypted_response_alg?: undefined | string;
	introspection_encrypted_response_enc?: undefined | string;
	authorization_signed_response_alg?: undefined | string;
	authorization_encrypted_response_alg?: undefined | string;
	authorization_encrypted_response_enc?: undefined | string;
};
```

</details>

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `client_id` | `string` | Client identifier issued or confirmed by registration; not valid in client publication metadata. |
| `client_secret?` | `undefined \| string` | Optional registration response secret; never publish it in an EC or Subordinate Statement. |
| `client_id_issued_at?` | `undefined \| number` | Nonnegative integer issuance time of the client identifier. |
| `client_secret_expires_at?` | `undefined \| number` | Nonnegative integer secret expiration; 0 means the secret does not expire. |
| `registration_access_token?` | `undefined \| string` | Optional nonempty registration-management token, returned together with registration_client_uri. The host must enforce read-only permissions when enabled. |
| `registration_client_uri?` | `undefined \| string` | HTTPS registration-management URL without a fragment, returned together with registration_access_token. |
| `jwks_uri?` | `undefined \| string` | HTTPS URL for public protocol keys, without a fragment. |
| `jwks?` | `undefined \| { [key: string]: unknown; keys: Array<JWK>; }` | JSON Web Key Set. The owning API determines whether these are Federation Entity Keys or protocol keys. |
| `sector_identifier_uri?` | `undefined \| string` | HTTPS URL for the client's sector identifier document. Parsing does not fetch the document. |
| `request_uris?` | `undefined \| Array<string>` | Registered Request Object URLs. |
| `subject_type?` | `undefined \| "public" \| "pairwise"` | Selected OIDC subject identifier type: public or pairwise; it must belong to any supplied subject_types_supported choices. |
| `id_token_signed_response_alg?` | `undefined \| string` | Selected signing algorithm for id token responses. |
| `id_token_encrypted_response_alg?` | `undefined \| string` | Selected key-management algorithm for id token response encryption. |
| `id_token_encrypted_response_enc?` | `undefined \| string` | Selected content-encryption method for id token responses. |
| `userinfo_signed_response_alg?` | `undefined \| string` | Selected signing algorithm for userinfo responses. |
| `userinfo_encrypted_response_alg?` | `undefined \| string` | Selected key-management algorithm for userinfo response encryption. |
| `userinfo_encrypted_response_enc?` | `undefined \| string` | Selected content-encryption method for userinfo responses. |
| `request_object_signing_alg?` | `undefined \| string` | Selected Request Object signing algorithm. |
| `request_object_encryption_alg?` | `undefined \| string` | Selected Request Object key-management algorithm. |
| `request_object_encryption_enc?` | `undefined \| string` | Selected Request Object content-encryption method. |
| `token_endpoint_auth_method?` | `undefined \| string` | Selected token endpoint authentication method; extension string values are preserved. |
| `token_endpoint_auth_signing_alg?` | `undefined \| string` | Signing algorithm for JWT client authentication; none is rejected. |
| `default_max_age?` | `undefined \| number` | Default authentication age in nonnegative integer seconds. |
| `require_auth_time?` | `undefined \| boolean` | Whether an authentication time claim is required by the client. |
| `default_acr_values?` | `undefined \| Array<string>` | Default requested authentication context class reference values. |
| `initiate_login_uri?` | `undefined \| string` | HTTPS URL at which the client accepts third-party initiated login. |
| `post_logout_redirect_uris?` | `undefined \| Array<string>` | Registered post-logout redirect URLs. |
| `backchannel_token_delivery_mode?` | `undefined \| "push" \| "poll" \| "ping"` | Selected CIBA mode: poll, ping, or push. Effective metadata enforces its grant and notification dependencies. |
| `backchannel_client_notification_endpoint?` | `undefined \| string` | HTTPS client notification endpoint, required for effective CIBA ping or push delivery. |
| `backchannel_authentication_request_signing_alg?` | `undefined \| string` | Signing algorithm for CIBA authentication requests. |
| `backchannel_user_code_parameter?` | `undefined \| boolean` | Whether the CIBA client uses the user_code parameter. |
| `client_registration_types?` | `undefined \| Array<string>` | Supported client registration modes. Additional string values remain permitted. |
| `signed_jwks_uri?` | `undefined \| string` | HTTPS URL for a signed protocol JWK Set, without a fragment. |
| `organization_identifier?` | `undefined \| string` | Organization identifier supplied as informational metadata. |
| `scope?` | `undefined \| string` | Space-separated OAuth scopes requested or registered for this client. |
| `organization_name?` | `undefined \| string` | Human-readable organization name. |
| `display_name?` | `undefined \| string` | Human-readable display name. |
| `description?` | `undefined \| string` | Human-readable description. |
| `keywords?` | `undefined \| Array<string>` | Informational search keywords; a supplied list must be nonempty. |
| `contacts?` | `undefined \| Array<string>` | Contact addresses; a supplied list must be nonempty. |
| `logo_uri?` | `undefined \| string` | Logo URL for the entity or Trust Mark described by this metadata. |
| `policy_uri?` | `undefined \| string` | Policy information URL. |
| `information_uri?` | `undefined \| string` | Additional entity information URL. |
| `organization_uri?` | `undefined \| string` | Organization website URL. |
| `frontchannel_logout_uri?` | `undefined \| string` | HTTPS front-channel logout URI, without a fragment. |
| `frontchannel_logout_session_required?` | `undefined \| boolean` | Whether the client requires session information for front-channel logout. |
| `backchannel_logout_uri?` | `undefined \| string` | HTTPS back-channel logout URI, without a fragment. |
| `backchannel_logout_session_required?` | `undefined \| boolean` | Whether the client requires session information for back-channel logout. |
| `redirect_uris?` | `undefined \| Array<string>` | Registered redirect URLs. The effective parser enforces flow-dependent presence and redirect security rules. |
| `response_types?` | `undefined \| Array<string>` | Client response types; effective metadata checks consistency with the grant types. |
| `grant_types?` | `undefined \| Array<string>` | Client grant types; conditional redirect, response-type, and CIBA requirements are checked by the parser. |
| `application_type?` | `undefined \| "web" \| "native"` | OIDC application type: web or native. Redirect requirements depend on this value and the flow. |
| `client_name?` | `undefined \| string` | Human-readable client name. |
| `client_uri?` | `undefined \| string` | Client information URL. |
| `tos_uri?` | `undefined \| string` | Client terms-of-service URL. |
| `subject_types_supported?` | `undefined \| Array<string>` | Supported OpenID Connect subject identifier types. |
| `id_token_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted id token signing algorithms. Parsing applies this field's protocol restrictions. |
| `id_token_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted id token encryption algorithms. Parsing applies this field's protocol restrictions. |
| `id_token_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted id token encryption content-encryption methods. |
| `userinfo_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted userinfo signing algorithms. Parsing applies this field's protocol restrictions. |
| `userinfo_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted userinfo encryption algorithms. Parsing applies this field's protocol restrictions. |
| `userinfo_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted userinfo encryption content-encryption methods. |
| `request_object_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted request object signing algorithms. Parsing applies this field's protocol restrictions. |
| `request_object_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted request object encryption algorithms. Parsing applies this field's protocol restrictions. |
| `request_object_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted request object encryption content-encryption methods. |
| `token_endpoint_auth_methods_supported?` | `undefined \| Array<string>` | Supported authentication methods for token endpoint. |
| `token_endpoint_auth_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted token endpoint auth signing algorithms. Parsing applies this field's protocol restrictions. |
| `backchannel_authentication_request_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted backchannel authentication request signing algorithms. Parsing applies this field's protocol restrictions. |
| `authorization_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted authorization signing algorithms. Parsing applies this field's protocol restrictions. |
| `authorization_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted authorization encryption algorithms. Parsing applies this field's protocol restrictions. |
| `authorization_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted authorization encryption content-encryption methods. |
| `introspection_signing_alg_values_supported?` | `undefined \| Array<string>` | Permitted introspection signing algorithms. Parsing applies this field's protocol restrictions. |
| `introspection_encryption_alg_values_supported?` | `undefined \| Array<string>` | Permitted introspection encryption algorithms. Parsing applies this field's protocol restrictions. |
| `introspection_encryption_enc_values_supported?` | `undefined \| Array<string>` | Permitted introspection encryption content-encryption methods. |
| `software_id?` | `undefined \| string` | Client software identifier. |
| `software_version?` | `undefined \| string` | Client software version. |
| `software_statement?` | `undefined \| string` | Software statement JWT preserved as metadata; parsing does not authenticate its signer. |
| `claims_redirect_uris?` | `undefined \| Array<string>` | Client URLs used for claims-redirection workflows. |
| `nfv_token_signed_response_alg?` | `undefined \| string` | Selected signing algorithm for nfv token responses. |
| `nfv_token_encrypted_response_alg?` | `undefined \| string` | Selected key-management algorithm for nfv token response encryption. |
| `nfv_token_encrypted_response_enc?` | `undefined \| string` | Selected content-encryption method for nfv token responses. |
| `tls_client_certificate_bound_access_tokens?` | `undefined \| boolean` | Whether this participant supports certificate-bound access tokens. |
| `tls_client_auth_subject_dn?` | `undefined \| string` | Expected certificate subject distinguished name. Effective tls_client_auth metadata requires exactly one certificate selector. |
| `tls_client_auth_san_dns?` | `undefined \| string` | Expected DNS subjectAltName. Effective tls_client_auth metadata requires exactly one certificate selector. |
| `tls_client_auth_san_uri?` | `undefined \| string` | Expected URI subjectAltName. Effective tls_client_auth metadata requires exactly one certificate selector. |
| `tls_client_auth_san_ip?` | `undefined \| string` | Expected IP subjectAltName. Effective tls_client_auth metadata requires exactly one certificate selector. |
| `tls_client_auth_san_email?` | `undefined \| string` | Expected email subjectAltName. Effective tls_client_auth metadata requires exactly one certificate selector. |
| `require_signed_request_object?` | `undefined \| boolean` | Whether Request Objects must be signed. |
| `require_pushed_authorization_requests?` | `undefined \| boolean` | Whether clients must use PAR. |
| `use_mtls_endpoint_aliases?` | `undefined \| boolean` | Whether the client requests the server's mutual-TLS endpoint aliases. |
| `authorization_details_types?` | `undefined \| Array<string>` | Authorization-details types requested by the client. |
| `dpop_bound_access_tokens?` | `undefined \| boolean` | Whether the client requests DPoP-bound access tokens. |
| `introspection_signed_response_alg?` | `undefined \| string` | Selected signing algorithm for introspection responses. |
| `introspection_encrypted_response_alg?` | `undefined \| string` | Selected key-management algorithm for introspection response encryption. |
| `introspection_encrypted_response_enc?` | `undefined \| string` | Selected content-encryption method for introspection responses. |
| `authorization_signed_response_alg?` | `undefined \| string` | Selected signing algorithm for authorization responses. |
| `authorization_encrypted_response_alg?` | `undefined \| string` | Selected key-management algorithm for authorization response encryption. |
| `authorization_encrypted_response_enc?` | `undefined \| string` | Selected content-encryption method for authorization responses. |

