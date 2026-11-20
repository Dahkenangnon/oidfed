# `@oidfed/oidc` API

[API reference](../README.md)

The package root exports the role classes and their OIDC and OAuth contracts. Import the shared types and authentication helpers below from `@oidfed/core`.

The class entries cover constructors and public members, including inherited instance methods and callable static properties. Metadata schema objects and standalone registration-processing functions are not root exports. Use role methods for processing and their static parsers for independent metadata checks.

A signature returning `Result` uses `ok`, `value`, and `error`. Metadata parsers instead use Zod's `success`, `data`, and `error.issues`. Some configuration, signing, and host-callback failures can throw or reject; the individual entries describe those cases.

## Identifiers, results, and host contracts

| API | Kind |
|---|---|
| [`EntityId`](../core/contracts.md#entityid-1) | Type; from @oidfed/core |
| [`FederationError`](../core/contracts.md#federationerror-1) | Type; from @oidfed/core |
| [`FederationOptions`](../core/contracts.md#federationoptions) | Interface; from @oidfed/core |
| [`Result`](../core/contracts.md#result) | Type; from @oidfed/core |
| [`TrustAnchorSet`](../core/contracts.md#trustanchorset) | Type; from @oidfed/core |

Standalone [client and endpoint authentication](../core/authentication.md) is available through Core.

## Metadata and wire types

| API | Kind |
|---|---|
| [`ExplicitRegistrationRequestPayload`](schemas.md#explicitregistrationrequestpayload) | Type |
| [`ExplicitRegistrationResponsePayload`](schemas.md#explicitregistrationresponsepayload) | Type |
| [`OAuthAuthorizationServerMetadata`](schemas.md#oauthauthorizationservermetadata) | Type |
| [`OAuthAuthorizationServerPublicationMetadata`](schemas.md#oauthauthorizationserverpublicationmetadata) | Type |
| [`OAuthClientMetadata`](schemas.md#oauthclientmetadata) | Type |
| [`OAuthClientPublicationMetadata`](schemas.md#oauthclientpublicationmetadata) | Type |
| [`OAuthClientRegistrationResponseMetadata`](schemas.md#oauthclientregistrationresponsemetadata) | Type |
| [`OAuthResourceMetadata`](schemas.md#oauthresourcemetadata) | Type |
| [`OAuthResourcePublicationMetadata`](schemas.md#oauthresourcepublicationmetadata) | Type |
| [`OIDCFederationMetadata`](schemas.md#oidcfederationmetadata) | Type |
| [`OIDCFederationPublicationMetadata`](schemas.md#oidcfederationpublicationmetadata) | Type |
| [`OpenIDProviderMetadata`](schemas.md#openidprovidermetadata) | Type |
| [`OpenIDProviderPublicationMetadata`](schemas.md#openidproviderpublicationmetadata) | Type |
| [`OpenIDRelyingPartyMetadata`](schemas.md#openidrelyingpartymetadata) | Type |
| [`OpenIDRelyingPartyPublicationMetadata`](schemas.md#openidrelyingpartypublicationmetadata) | Type |
| [`OpenIDRelyingPartyRegistrationResponseMetadata`](schemas.md#openidrelyingpartyregistrationresponsemetadata) | Type |

## Registration and protocol keys

| API | Kind |
|---|---|
| [`AutomaticRegistrationResult`](registration.md#automaticregistrationresult) | Type |
| [`ExplicitRegistrationResult`](registration.md#explicitregistrationresult) | Interface |
| [`PreparedPushedAuthorizationRequest`](registration.md#preparedpushedauthorizationrequest) | Interface |
| [`ProcessAutomaticRegistrationOptions`](registration.md#processautomaticregistrationoptions) | Interface |
| [`ProcessedAutomaticRegistration`](registration.md#processedautomaticregistration) | Interface |
| [`ProcessedPushedAuthorizationRequest`](registration.md#processedpushedauthorizationrequest) | Interface |
| [`ProcessedRegistration`](registration.md#processedregistration) | Interface |
| [`ProcessPushedAuthorizationRequestOptions`](registration.md#processpushedauthorizationrequestoptions) | Interface |
| [`PushedAuthorizationProof`](registration.md#pushedauthorizationproof) | Type |
| [`RegistrationAccreditationContext`](registration.md#registrationaccreditationcontext) | Interface |
| [`RegistrationAccreditationPolicy`](registration.md#registrationaccreditationpolicy) | Interface |
| [`RegistrationProtocolAdapter`](registration.md#registrationprotocoladapter) | Interface |
| [`RegistrationProtocolAdapterContext`](registration.md#registrationprotocoladaptercontext) | Interface |
| [`RequestDelivery`](registration.md#requestdelivery) | Type |

## Protocol roles and configuration

| API | Kind |
|---|---|
| [`CreateAuthorizationRequestOptions`](roles.md#createauthorizationrequestoptions) | Interface |
| [`OAuthAuthorizationServerRole`](roles.md#oauthauthorizationserverrole) | Class |
| [`OAuthAuthorizationServerRoleConfig`](roles.md#oauthauthorizationserverroleconfig) | Type |
| [`OAuthClientRole`](roles.md#oauthclientrole) | Class |
| [`OAuthClientRoleConfig`](roles.md#oauthclientroleconfig) | Type |
| [`OAuthResourceRole`](roles.md#oauthresourcerole) | Class |
| [`OAuthResourceRoleConfig`](roles.md#oauthresourceroleconfig) | Interface |
| [`OidcProviderRole`](roles.md#oidcproviderrole) | Class |
| [`OidcProviderRoleConfig`](roles.md#oidcproviderroleconfig) | Interface |
| [`OidcRelyingPartyRole`](roles.md#oidcrelyingpartyrole) | Class |
| [`OidcRelyingPartyRoleConfig`](roles.md#oidcrelyingpartyroleconfig) | Interface |

