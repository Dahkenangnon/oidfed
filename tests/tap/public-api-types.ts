import {
	type EntityStatementMetadata,
	type FederationKeyProvider,
	type FederationSigningKey,
	type JWKSet,
	MemoryFederationKeyProvider,
} from "@oidfed/core";
import type { LeafConfig } from "@oidfed/leaf";
import type {
	FedOauthProviderConfig,
	FedOauthResourceConfig,
	FedOidcProviderConfig,
	RegistrationProtocolAdapter,
} from "@oidfed/oidc";

declare const federationKeyProvider: FederationKeyProvider;
declare const federationSigningKey: FederationSigningKey;

const leafMetadata = {
	federation_entity: { organization_name: "Example Leaf" },
	custom_protocol: { display_name: "Custom" },
} satisfies EntityStatementMetadata;

const leafConfig = {
	entityId: "https://leaf.example.com",
	authorityHints: ["https://ta.example.com"],
	metadata: leafMetadata,
	keyProvider: federationKeyProvider,
} satisfies LeafConfig;
void leafConfig;

const leafConfigWithScalarMetadata = {
	entityId: "https://leaf.example.com",
	authorityHints: ["https://ta.example.com"],
	// @ts-expect-error Entity Statement metadata values must be JSON objects.
	metadata: { openid_relying_party: "bad" },
	keyProvider: federationKeyProvider,
} satisfies LeafConfig;
void leafConfigWithScalarMetadata;

const registrationAdapter: RegistrationProtocolAdapter = {
	validateClientMetadata: (raw) => ({ ok: true, value: raw }),
	enrichResponseMetadata: (rpMeta) => rpMeta,
};

const oidcProviderConfig = {
	registrationProtocolAdapter: registrationAdapter,
} satisfies FedOidcProviderConfig;
void oidcProviderConfig;

const oauthProviderConfig = {
	registrationProtocolAdapter: registrationAdapter,
} satisfies FedOauthProviderConfig;
void oauthProviderConfig;

const incompleteRegistrationAdapter = {
	validateClientMetadata: (raw: Record<string, unknown>) => ({ ok: true, value: raw }),
};

const oidcProviderConfigWithIncompleteAdapter = {
	// @ts-expect-error registrationProtocolAdapter must implement the full adapter contract.
	registrationProtocolAdapter: incompleteRegistrationAdapter,
} satisfies FedOidcProviderConfig;
void oidcProviderConfigWithIncompleteAdapter;

const resourceJwks = {
	keys: [{ kty: "EC", kid: "resource-key-1", crv: "P-256", x: "x", y: "y" }],
} satisfies JWKSet;

const oauthResourceConfig = {
	jwks: resourceJwks,
} satisfies FedOauthResourceConfig;
void oauthResourceConfig;

const oauthResourceConfigWithInvalidJwks = {
	// @ts-expect-error jwks must satisfy the core JWKSet shape.
	jwks: { keys: ["not-a-jwk"] },
} satisfies FedOauthResourceConfig;
void oauthResourceConfigWithInvalidJwks;

void new MemoryFederationKeyProvider(federationSigningKey);
void new MemoryFederationKeyProvider([federationSigningKey]);

// @ts-expect-error an initial federation signing key is required.
void new MemoryFederationKeyProvider();

// @ts-expect-error initial key arrays must be non-empty.
void new MemoryFederationKeyProvider([]);
