import type { AuthorityConfig } from "@oidfed/authority";
import type { FederationStorage } from "@oidfed/core";
import {
	type CryptoContext,
	decodeEntityConfiguration,
	decodeSubordinateStatement,
	type EntityConfigurationPayload,
	type EntityStatementMetadata,
	type JWKSet,
	type SubordinateStatementPayload,
	type TrustAnchorSet,
} from "@oidfed/core";
import type { LeafConfig } from "@oidfed/leaf";
import type {
	OAuthAuthorizationServerRoleConfig,
	OAuthResourceRoleConfig,
	OidcProviderRoleConfig,
	OpenIDRelyingPartyMetadata,
	OpenIDRelyingPartyRegistrationResponseMetadata,
	RegistrationProtocolAdapter,
} from "@oidfed/oidc";

declare const federationKeyProvider: CryptoContext;
declare const federationKeyLifecycleProvider: CryptoContext;
declare const engine: import("@oidfed/crypto").CryptoEngine;
declare const keyring: import("@oidfed/crypto").RotatingKeyring;
declare const signer: import("@oidfed/crypto").Signer;
declare const trustAnchors: TrustAnchorSet;
declare const authorityStorage: FederationStorage;

const leafMetadata = {
	federation_entity: { organization_name: "Example Leaf" },
	custom_protocol: { display_name: "Custom" },
} satisfies EntityStatementMetadata;

const leafConfig = {
	entityId: "https://leaf.example.com",
	authorityHints: ["https://ta.example.com"],
	trustAnchorHints: ["https://preferred-ta.example.com"],
	trustAnchors,
	metadata: leafMetadata,
	crypto: federationKeyProvider,
} satisfies LeafConfig;
void leafConfig;

const intermediateAuthorityConfig = {
	entityId: "https://authority.example.com",
	authorityHints: ["https://ta.example.com"],
	trustAnchorHints: ["https://preferred-ta.example.com"],
	metadata: {
		federation_entity: {
			federation_fetch_endpoint: "https://authority.example.com/federation_fetch",
			federation_list_endpoint: "https://authority.example.com/federation_list",
		},
	},
	storage: authorityStorage,
	crypto: federationKeyLifecycleProvider,
} satisfies AuthorityConfig;
void intermediateAuthorityConfig;

const leafConfigWithScalarMetadata = {
	entityId: "https://leaf.example.com",
	authorityHints: ["https://ta.example.com"],
	// @ts-expect-error Entity Statement metadata values must be JSON objects.
	metadata: { openid_relying_party: "bad" },
	crypto: federationKeyProvider,
} satisfies LeafConfig;
void leafConfigWithScalarMetadata;

const rpEntityMetadata = {
	redirect_uris: ["https://rp.example.com/callback"],
	custom_extension: "allowed",
} satisfies OpenIDRelyingPartyMetadata;
void rpEntityMetadata;

const rpEntityMetadataWithResponseField = {
	redirect_uris: ["https://rp.example.com/callback"],
	// @ts-expect-error client_id is response metadata, not RP Entity Configuration metadata.
	client_id: "client-123",
} satisfies OpenIDRelyingPartyMetadata;
void rpEntityMetadataWithResponseField;

const rpRegistrationResponseMetadata = {
	client_id: "client-123",
	client_secret: "secret-123",
	client_id_issued_at: 1,
	client_secret_expires_at: 2,
} satisfies OpenIDRelyingPartyRegistrationResponseMetadata;
void rpRegistrationResponseMetadata;

const registrationAdapter: RegistrationProtocolAdapter = {
	validateClientMetadata: () => ({ ok: true, value: undefined }),
};

const oidcProviderConfig = {
	registrationProtocolAdapter: registrationAdapter,
} satisfies OidcProviderRoleConfig;
void oidcProviderConfig;

const oauthProviderConfig = {
	registrationProtocolAdapter: registrationAdapter,
} satisfies OAuthAuthorizationServerRoleConfig;
void oauthProviderConfig;

const incompleteRegistrationAdapter = {};

const oidcProviderConfigWithIncompleteAdapter = {
	// @ts-expect-error registrationProtocolAdapter must provide a validation hook.
	registrationProtocolAdapter: incompleteRegistrationAdapter,
} satisfies OidcProviderRoleConfig;
void oidcProviderConfigWithIncompleteAdapter;

const resourceJwks = {
	keys: [{ kty: "EC", kid: "resource-key-1", crv: "P-256", x: "x", y: "y" }],
} satisfies JWKSet;

const oauthResourceConfig = {
	jwks: resourceJwks,
} satisfies OAuthResourceRoleConfig;
void oauthResourceConfig;

const oauthResourceConfigWithInvalidJwks = {
	// @ts-expect-error jwks must satisfy the core JWKSet shape.
	jwks: { keys: ["not-a-jwk"] },
} satisfies OAuthResourceRoleConfig;
void oauthResourceConfigWithInvalidJwks;

void keyring.publish("federation", signer);
void keyring.activate("federation", "next-key");
void keyring.retire("federation", "previous-key");
void keyring.revoke("federation", "old-key", "compromised");
const explicitCrypto = { engine, keyring } satisfies CryptoContext;
void explicitCrypto;
// @ts-expect-error a host requires its engine as well as a keyring.
const incompleteCrypto: CryptoContext = { keyring };
void incompleteCrypto;

declare const entityConfigurationJwt: string;
declare const subordinateStatementJwt: string;

const decodedEntityConfiguration = decodeEntityConfiguration(entityConfigurationJwt);
if (decodedEntityConfiguration.ok) {
	const payload: EntityConfigurationPayload = decodedEntityConfiguration.value.payload;
	const subject: string = payload.sub;
	void subject;
}

const decodedSubordinateStatement = decodeSubordinateStatement(subordinateStatementJwt);
if (decodedSubordinateStatement.ok) {
	const payload: SubordinateStatementPayload = decodedSubordinateStatement.value.payload;
	const issuer: string = payload.iss;
	const subject: string = payload.sub;
	void issuer;
	void subject;
}

const readOnlyRegistration = {
	registrationManagement: "read-only",
} satisfies OidcProviderRoleConfig;
const disabledRegistration = {
	registrationManagement: "disabled",
} satisfies OAuthAuthorizationServerRoleConfig;
void readOnlyRegistration;
void disabledRegistration;
const writableRegistration = {
	// @ts-expect-error Federation registration access cannot enable modification.
	registrationManagement: "writable",
} satisfies OidcProviderRoleConfig;
void writableRegistration;
