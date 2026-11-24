# Migrate to oidfed v3

| Area | What changes |
| --- | --- |
| [Installation and imports](#dependencies-and-imports) | oidfed installs its runtime dependencies. Shared APIs belong to Core. |
| [Crypto](#host-provided-crypto) | The application supplies cryptographic operations, signing keys, and rollover timing. |
| [Hosts and registration](#authority-and-role-configuration) | Hosts initialize asynchronously. Roles inherit crypto and storage from their host. |
| [Storage](#federation-storage) | Each host uses one storage handle with repositories for the features it serves. |

For additional breaking changes, see the v3 entries when published in the package changelogs. [Core](../../packages/core/CHANGELOG.md) · [Authority](../../packages/authority/CHANGELOG.md) · [Leaf](../../packages/leaf/CHANGELOG.md) · [OIDC](../../packages/oidc/CHANGELOG.md) · [Wallet](../../packages/wallet/CHANGELOG.md) · [CLI](../../tools/cli/CHANGELOG.md)

## Dependencies and imports

| Before | In v3 |
| --- | --- |
| Install Zod to satisfy an oidfed peer | Core, OIDC, and Wallet install Zod. Keep a direct dependency if your app imports it. Use the same resolved version when [composing schemas](core/schemas.md#compose-schemas). |
| Import shared types, errors, or helpers from a host or role package | Import them from `@oidfed/core` and declare it directly. This includes storage types, `DiscoveryResult`, `TrustAnchorSet`, and shared client assertion and attestation helpers. |
| Authority’s `ExtendedSubordinateListingParams` | Core’s `ExtendedListRequestParams`. |
| Wallet’s `WalletAttestation`, `CreateWalletAttestationParams`, and `parseConcatenatedWalletAttestation` | Core’s `ClientAttestation`, `CreateClientAttestationParams`, and `parseConcatenatedClientAttestation`. |
| Static discovery, assessment, or sanitization on a host | Use Core’s `discoverEntity`, `discoverEntityFromChain`, `assessEntity`, or `sanitizeSubordinateMetadata`. Convert raw IDs with `entityId(id)` for standalone discovery. |

## Host-provided crypto

### Configure a host

| Before | In v3 |
| --- | --- |
| Synchronous host constructor | Await `Leaf.create()`, `TrustAnchor.create()`, or `Intermediate.create()`. The factory initializes the attached roles. |
| Federation and protocol key providers or a full-token signer | Pass `crypto: { engine, keyring }`. The keyring selects a `KeyringEntry` that binds public keys to a byte signer. |
| Core key generation | Generate keys in your backend or use the CLI’s `keygen`. Install `@oidfed/crypto` directly when importing its contracts or adapters. |

See the [wiring example](../features/11.5.http-wiring.md#1-create-the-trust-anchor) and the [crypto contracts and adapters](crypto/README.md).

### Separate federation and protocol purposes

Replace protocol key providers with each role’s `signing` settings. Use `requestObject` and `clientAssertion` for an RP, `walletAttestation` for a Wallet Provider, and `authorizationRequest` for a Credential Verifier. Configure explicit keyring aliases when operations share a key.

Managed roles derive inline JWKS from the selected purposes. Remove explicit `jwks`, `jwks_uri`, and `signed_jwks_uri` from metadata for those roles. Hosts use the same keyring snapshot to publish keys and sign. [OIDC role setup](../features/15.1.oidc-roles.md) · [Wallet role setup](../features/16.1.wallet-roles.md)

### Verify tokens and bind policy

| Before | In v3 |
| --- | --- |
| Standalone verification uses an implicit backend | Pass `{ engine }` to helpers such as `verifyEntityStatement()`. Instance methods use their host’s engine. |
| Federation signing and verification use `allowedAlgorithms` | Set `allowedFederationAlgorithms` for Federation Entity Keys. Protocol keys use their own options. |
| `SUPPORTED_ALGORITHMS` or `REQUIRED_ALGORITHMS` | Use `DEFAULT_ALLOWED_ALGORITHMS` for the default policy and `INTEROP_RECOMMENDED_ALGORITHMS` for interop guidance. |

Review limits for compact token size and verification candidates where the app sets custom policy. [JWS service](core/contracts.md#jwsservice) · [Custom algorithm example](../examples/custom-crypto.ts)

`RS384` and `RS512` are built-in algorithms. Remove custom definitions that use either identifier and enable the stock implementation in your crypto adapter and allowlist where you need it. The default allowlist is unchanged. Custom algorithms can still use their own identifiers.

When a managed Federation endpoint offers `private_key_jwt`, make sure it can verify every algorithm in `endpoint_auth_signing_alg_values_supported`. The declaration is optional. The engine, Federation algorithm policy, client-assertion policy, and endpoint restrictions all apply. [Endpoint authentication](../features/7.5.endpoint-authentication.md)

### Publish and retire keys deliberately

Replace automatic retirement with a host schedule. Publish the next key, allow for propagation, activate it, then call `keyring.retire()` after your overlap window. Supply `crypto.history`, for example with `historicalKeysFromKeyring(keyring)`, when serving Historical Keys. [Key rollover](../features/9.5.key-rollover.md)

## Authority and role configuration

| Before | In v3 |
| --- | --- |
| Mount the authority through its server delegate or middleware type | Call `authority.handleRequest(request)` on the instance returned by the factory. |
| Optional hints on an Intermediate or Trust Mark issuer policy on an Intermediate | Supply at least one `authorityHints` entry on an Intermediate. Manage Trust Mark issuer and owner policy on the Trust Anchor. |
| Supply crypto or storage to individual hosted operations | Configure both on the host. Pass per-call policy and limits, such as a clock or timeout, through the bound options. |

## OIDC registration

| Before | In v3 |
| --- | --- |
| Configure `new OIDCRegistrationAdapter()` for ordinary provider setup | Use the provider role’s registration methods. The role validates effective client metadata and supplies the default `client_id` in explicit registration responses. |
| An adapter receives a client metadata block or transforms an explicit response block | Validate the full effective metadata map in `validateClientMetadata()`. Use `context.clientMetadataType` to identify the client block. Transform the full response map in `enrichResponseMetadata()`. |

See the [registration adapters guide](../features/15.7.registration-adapters.md) for examples.

## Federation storage

| Before | In v3 |
| --- | --- |
| Authority `StorageAdapter` or `MemoryStorageAdapter` | Pass a `FederationStorage` or `MemoryFederationStorage` from Core. Declare the capabilities your host uses. |
| `subordinates.get/add` and `subordinateEvents.list` | Use `subordinate.fetch/register` and `subordinateEvent.history`. Pass the host’s update time to `subordinate.update`. |
| `trustMarks` or `MemoryTrustMarkStore` | Use `storage.trustMark`. Rename `listCandidates/getByJwt/getValid/listValid/listValidForSubject/hasAnyValid` to `candidates/status/valid/listSubjects/forSubject/hasAny`. Implement `revision()` and transactional `checkRevision()`. |
| `collection.store`, `storage.collections`, or an implicit memory store | Supply `storage.entityCollection` explicitly. Rename `getCurrent/getSnapshot/putCursor/getCursor` to `current/snapshot/saveCursor/cursor`. |
| Per-role or standalone `replayStore` | Use the host’s `storage.replay` or standalone `options.storage.replay`. JTI attestation policy uses `{ mode: "jti" }`. |
| `FederationOptions.cache`, Resolve `cache`, or `MemoryCache` | Use `storage.cache` and pass the engine to cache-key helpers. |

Authorities need subordinate reads. A publication-only Leaf can omit storage. Automatic registration, hosted PAR, and authenticated Collection require replay storage. Use the [storage reference](core/storage.md) to update repository methods. For existing data, follow the [cutover and rollback steps](../features/11.6.storage-adapters.md#cut-over-a-durable-deployment) before switching writers.
