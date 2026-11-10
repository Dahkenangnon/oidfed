# @oidfed/wallet

`@oidfed/wallet` implements the federation trust layer of [OpenID Federation for Wallet Architectures 1.0, Draft 05](https://openid.net/specs/openid-federation-wallet-1_0-05.html). It adds Wallet Provider, Credential Issuer, and Credential Verifier roles to the existing authority and leaf hosts.

The package validates federation evidence and applies the wallet profile's metadata and policy rules. Your OpenID4VCI/OpenID4VP implementation owns its protocol endpoints, sessions, credential selection, presentation processing, and credential formats.

See [wallet federation responsibilities](../guide/operator-responsibilities.md#wallet-federation-draft-05) for verification callbacks, protocol keys, replay storage, provider revalidation, and offline evidence lifetimes.

Wallet trust results expose the chain's verified marks and individual mark outcomes. Apply application accreditation requirements with [`checkTrustMarkRequirements()`](core.md#trust-marks) before using an entity for an operation that requires those marks. Federation chain validation alone establishes no required accreditation.

## Compose roles into a host

```ts
import { Leaf } from "@oidfed/leaf";
import { CredentialVerifierRole } from "@oidfed/wallet";

const verifier = new CredentialVerifierRole({
  metadata: {
    vp_formats_supported: { "dc+sd-jwt": {} },
    jwks: verifierProtocolPublicKeys,
    request_uris: ["https://verifier.example/request"],
    response_uris: ["https://verifier.example/response"],
    redirect_uris: ["https://verifier.example/done"],
  },
});

const host = new Leaf({
  entityId: "https://verifier.example",
  authorityHints: ["https://authority.example"],
  metadata: { federation_entity: {} },
  keyProvider: federationKeyProvider,
  trustAnchors,
  roles: [verifier],
});

const response = await host.handleRequest(request);
```

`WalletProviderRole` uses `openid_wallet_provider`, `CredentialIssuerRole` uses `openid_credential_issuer`, and `CredentialVerifierRole` uses `openid_credential_verifier`. The same roles can be attached to `TrustAnchor` and `Intermediate`. Create a fresh role instance for each host.

Hosts compose role metadata with their own metadata, then call the optional `EntityRole.validateMetadata` hook before publication. Role configuration takes precedence over fields supplied by the host. Wallet roles validate supplied fields, including exact equality between a supplied `credential_issuer` and the host's Entity Identifier. Publication accepts partial or empty blocks so a superior can complete them, as allowed by [Federation §5](https://openid.net/specs/openid-federation-1_0.html#section-5) and [Wallet §7.1](https://openid.net/specs/openid-federation-wallet-1_0-05.html#section-7.1).

Effective provider and verifier metadata require `vp_formats_supported`. Issuers require `credential_issuer`, `credential_endpoint`, and `credential_configurations_supported`, with the nested requirements from OpenID4VCI. Metadata extensions are preserved. The three roles expose `parseMetadata(value)` to validate complete effective metadata without a host.

Issuer discovery and `CredentialIssuerRole.parseMetadata()` validate completed encryption metadata. An advertised `credential_request_encryption.jwks` needs at least one key with a nonempty encryption `alg` whose declared `use` and `key_ops` permit encryption or key agreement, as required for key selection by [OpenID4VCI §10](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-10). Mixed sets are accepted. Known signing algorithms and `none` cannot satisfy this check; extension algorithms remain available to the application’s crypto implementation. Required response encryption also needs request-encryption support, since [§8.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.2) requires encrypted transport of the response-encryption parameters. Publication allows a superior to supply these missing encryption fields. The application chooses a usable algorithm and performs encryption.

Issuer claim descriptions follow the credential format. [OpenID4VCI mdoc paths](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-C.2) start with namespace and data-element strings and can continue into CBOR maps, including integer keys, or arrays. JSON paths use nonnegative array indices. [OpenID4VP mdoc query paths](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-7.2) contain exactly the namespace and data-element strings.

Claim-path wildcards are preserved when hosts publish metadata and when core validates the signed statements. Null metadata fields outside those path arrays remain invalid.

## Discover a trusted participant

Wallet applications can use static methods without a federation identity:

```ts
import { CredentialIssuerRole, WalletProviderRole } from "@oidfed/wallet";

const issuer = await CredentialIssuerRole.discover(issuerId, trustAnchors);
if (!issuer.ok) throw new Error(issuer.error.description);

const provider = await WalletProviderRole.discover(providerId, trustAnchors);
if (!provider.ok) throw new Error(provider.error.description);
```

Discovery returns effective role metadata and a validated trust chain. Issuer discovery also validates the federation identities of the listed authorization servers. When `authorization_servers` is absent, it uses the issuer itself and requires its `oauth_authorization_server` metadata. If any credential configuration omits `scope`, at least one discovered server must advertise `openid_credential` in `authorization_details_types_supported`, following [OpenID4VCI §12.2.4](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.2.4).

Issuer discovery uses `authorizationServerPolicy: "all"` by default. Set it to `"available"` to receive usable federation-validated servers in `authorizationServers` and failures in `authorizationServerErrors`. Discovery still fails if none are usable, the operation is cancelled, or its shared fetch budget is exhausted. [OpenID4VCI §12.2.4](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.2.4) allows the wallet to select a listed server; the application selects one suitable for its flow and checks any Credential Offer server hint against the advertised list. Cached use requires both the issuer's `trustChain.expiresAt` and the selected server's `trustChain.expiresAt` to remain current.

The application dispatches supported client identifier prefixes and keeps its wallet metadata consistent with that support. [OpenID4VP §10.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-10.1) defines `client_id_prefixes_supported`; omission advertises `pre-registered`. Include `openid_federation` when offering the federation request flow. Unknown metadata remains available for application-defined extensions; the schemas validate recognized fields in their specified locations.

Use existing List or Entity Collection APIs to find candidates, then discover each selected issuer independently. Collection data is informational. Applications choose when to repeat provider discovery to check current federation standing.

Discovery, verification, and signed-object creation accept core's HTTP client, clock, cancellation signal, cache, timeout, response-size limit, and fetch limits. Each operation shares its fetch budget across participant discovery, authorization-server discovery, and protocol-key retrieval. The default is 50 network calls.

`trustChain` supplies a preconstructed chain for the target. `entityChains` supplies additional chains keyed by subject. Every supplied chain is checked against the caller's pinned anchors. Explicit `trustChain` takes precedence over the matching `entityChains` entry; either is authoritative for that operation. Inline Request Objects use the header chain when present, otherwise the payload `trust_chain` permitted by [OpenID4VP §5.9.3](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.9.3). Completion removes this discovery hint from `request` and returns validated evidence through `trustChain`. Embedded attestation and inline Request Object chains are [hints](https://openid.net/specs/openid-federation-wallet-1_0-05.html#section-9): when caller evidence is absent, the library tries the hint, then uses bounded online discovery if it cannot establish trust. Invalid header shapes, empty chains, and chains exceeding configured limits fail before discovery. Chains containing malformed statements can fall back to online discovery. A failed object signature does not trigger another discovery attempt. `offline: true` blocks library network requests during discovery, verification, and creation of Wallet Attestations and Request Objects. Keep application verification callbacks and custom signers offline too.

For multi-hop chains, validation also needs each intermediate's signed Entity Configuration to check its `authority_hints`. Discovery retains these ECs with each candidate, so validation reuses them even when the configured cache does not retain entries. For supplied chains, pass `entityConfigurations`, a map from exact Entity Identifier to signed EC JWT, or preload the ECs in the configured core cache. These inputs still undergo identity, signature, and claim validation.

Existing offline multi-hop integrations must supply this additional EC evidence: `trustChain` and `entityChains` contain the serialized statements, which omit intermediate ECs. A supplied chain without the required local ECs fails validation without making HTTP calls. Supply the protocol keys needed by the selected operation as well. These options also apply to external authorization-server chains.

```ts
const provider = await WalletProviderRole.discover(providerId, trustAnchors, {
  offline: true,
  trustChain: providerTrustChain,
  entityConfigurations: new Map([
    [intermediateId, intermediateEcJwt],
  ]),
});
```

When set, `maxTotalFetches` must be a positive safe integer, including for offline operations; the network guard still prevents requests when `offline: true`.

## Sign and verify Wallet Attestations

```ts
import { CredentialIssuerRole } from "@oidfed/wallet";

const signed = await providerRole.createWalletAttestation(
  {
    subject: "wallet-type-client-id",
    confirmationKey: walletInstancePublicKey,
    expiresAt: Math.floor(Date.now() / 1000) + 600,
    claims: { wallet_name: "Example Wallet" },
  },
  providerProtocolSigner,
);

if (!signed.ok) throw new Error(signed.error.description);
const verified = await CredentialIssuerRole.verifyWalletAttestation(
  signed.value,
  trustAnchors,
);
```

The built-in JWT format follows OpenID4VCI 1.0 Appendix E and its referenced OAuth Attestation Client Authentication Draft 07. Provider trust is checked before the attestation signature. `verifyWalletAttestation` checks trust and cryptographic validity; application-specific acceptance remains a separate decision.

Attestation creation accepts public RSA and EC confirmation keys compatible with a supported signature algorithm. The confirmation key binds the instance's asymmetric proof of possession under [ACA Draft 07 §§5.1–5.2](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-07.html#section-5); its `kid` is optional. Unsupported key types and private key material return an error before signing.

Protocol operations use a core `JwtSigner`. Their remote keys come from the effective role metadata through core's key resolver. Effective inline `jwks` takes precedence over URI representations so a superior's replacement set cannot be bypassed. Top-level federation keys are not substituted automatically. Wallet Draft 05 does not define a provider attestation-key field; publishing provider protocol keys as `jwks`, `jwks_uri`, or `signed_jwks_uri` is this integration's convention and must match the deployed framework.

Issuer protocol keys follow [Wallet Draft 05 §6.2.1](https://openid.net/specs/openid-federation-wallet-1_0-05.html#section-6.2.1) and [Federation §5.2.1](https://openid.net/specs/openid-federation-1_0.html#section-5.2.1): `kid` is optional. The provider integration convention accepts the same key representation. Distinct identifiers are recommended by [RFC 7517 §4.5](https://www.rfc-editor.org/rfc/rfc7517.html#section-4.5); these sets can also contain keys sharing an identifier. When a set contains both signing and encryption keys, every key must declare `use`.

Verifier keys require unique, nonempty identifiers under [Wallet Draft 05 §6.3.1](https://openid.net/specs/openid-federation-wallet-1_0-05.html#section-6.3.1), including keys obtained through URI references. The same requirement applies to `credential_request_encryption.jwks` under [OpenID4VCI §12.2.4](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.2.4) and to top-level federation signing keys under [Federation §3.1.1](https://openid.net/specs/openid-federation-1_0.html#section-3.1.1).

For authentication, also verify proof of possession and use a shared replay store:

```ts
const authenticated = await CredentialIssuerRole.authenticateWallet(
  walletAttestationJwt,
  walletPopJwt,
  trustAnchors,
  {
    audience: authorizationServerIssuer,
    clientId: requestClientId,
    expectedChallenge,
    replayStore,
    acceptWallet: async ({ attestation, provider }, signal) =>
      frameworkPolicy.acceptWallet(attestation, provider, signal),
  },
);
```

The attestation and PoP have distinct JWT types and signing keys. PoP verification uses the public `cnf.jwk` inside the attestation. The PoP issuer must match the attestation subject and any supplied request client identifier. The audience is the authorization server's issuer identifier, including when the authorization server is separate from the Credential Issuer.

A supplied `expectedChallenge` must be nonblank and matches the proof exactly. The application generates, binds, and retains the server challenge. Freshness uses the PoP’s `iat`; server-timestamp-based challenge freshness, permitted by [ACA §12.1](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-07.html#section-12.1), remains an optional capability outside this API.

Use `allowedAttestationAlgorithms` and `allowedProofAlgorithms` to narrow the algorithms accepted during authentication. Standalone attestation verification also accepts `allowedAttestationAlgorithms`. Each configured list must be nonempty and contain algorithms supported by the library. Omission uses the supported set. Publish those same choices in the authorization server metadata required by [ACA §10.1](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-07.html#section-10.1); [§9](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-07.html#section-9) requires acceptance under local policy.

Attestation creation and verification require a usable public confirmation key with signature-verification usage. The `cnf` object uses `jwk` alone among the `jwk`, `jwe`, and `jku` representations, following [RFC 7800 §§3.1–3.2](https://www.rfc-editor.org/rfc/rfc7800.html#section-3.1). Unknown confirmation extensions remain uninterpreted. Authentication checks locally detectable proof failures before provider discovery and claims the replay identifier only after verification and application acceptance.

The default PoP freshness window is 300 seconds, configurable through `maxProofAgeSeconds`. Core's clock-skew tolerance also applies. This duration and the required caller-supplied `ReplayStore` are library policies. The store must claim identifiers atomically and retain them through the acceptance window. Authentication rejects replay-store failures; `MemoryReplayStore` is available for development.

An attestation's `iat` and a PoP's `exp` are optional. A PoP still requires `iat` and `jti`. The formats do not require a JWT `kid`; usable trusted public keys remain necessary. Attestation subjects can be shared by a wallet implementation and must not be treated as unique federation identifiers.

Creation preserves an omitted `iat` and accepts historical issuance dates supplied by the caller, who is responsible for their accuracy. It rejects future `iat`, expired `exp`, and `nbf >= exp`; delayed activation before expiry is valid under [ACA §5.1](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-07.html#section-5.1). Embedded-chain expiry does not cap attestation expiry, although offline verification needs a currently valid chain.

JWT type checks accept media-type case variants and the optional `application/` prefix under [RFC 7515 §4.1.9](https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.9). Producers use the canonical type names.

Applications displaying `wallet_name` or `wallet_link` choose safe text rendering and navigable URL schemes; successful signature verification establishes the claims’ origin.

For [ACA §7 concatenated serialization](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-07.html#section-7), `parseConcatenatedWalletAttestation(value, options)` returns `{ attestationJwt, popJwt }` in a `Result`. It requires exactly two nonempty compact JWTs separated by one `~` and applies `maxResponseBytes` to the complete value. Pass the pair to `authenticateWallet` for trust, signature, and claim verification.

The application parses any authentication headers. OAuth Draft 07 requires exactly one attestation field and one PoP field, each containing one well-formed JWT. Pass that validated pair to the authentication operation.

For standalone Wallet Attestation verification, supply `expectedAudience` when the token contains `aud`. Authentication uses its configured authorization-server audience for this check. An attestation without `aud` remains usable under ACA; the PoP always binds the recipient. The `acceptWallet` callback applies the framework's attestation status and acceptance policy.

## Create a signed presentation request

Request scopes follow [RFC 6749 §3.3](https://www.rfc-editor.org/rfc/rfc6749.html#section-3.3): a request may contain space-separated tokens, while a credential configuration advertises one token. Recognized DCQL authority constraints validate Federation Entity Identifiers and base64url `aki` values; custom authority types remain open.

Format identifiers must be nonblank. Format-specific algorithm fields are optional and extension fields are preserved. Completion checks active query formats against effective `vp_formats_supported`; creation applies the same check when supplied with a validated chain and a concrete query or scope mapping. Superior query overrides determine which queries are active. Credential-format processing and cryptographic capability checks belong to the application.

```ts
const created = await CredentialVerifierRole.createAuthorizationRequest(
  verifierEntityId,
  {
    response_type: "vp_token",
    response_mode: "direct_post",
    response_uri: "https://verifier.example/response",
    nonce: sessionNonce,
    dcql_query: presentationQuery,
  },
  protocolSigner,
);
if (!created.ok) throw new Error(created.error.description);
const requestObject = created.value;
```

The helper sets the `openid_federation:` client identifier and wallet audience, validates the request parameters, and signs with the supplied protocol signer. `direct_post` requires `response_uri` and prohibits `redirect_uri` in the Authorization Request ([OpenID4VP §8.2](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.2)). The same rules apply to [`direct_post.jwt`](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.3.1). A request cannot contain both URI parameters. The helper requires `redirect_uri` for `fragment` and accepts nonblank extension response modes for application-defined processing. Mode names are compared exactly.

Supplied response and redirect URIs must be HTTPS URLs, matching [Wallet Draft 05 §6.3.1](https://openid.net/specs/openid-federation-wallet-1_0-05.html#section-6.3.1). Invalid response parameters return `invalid_request` before signing or trust-chain preparation. Without a supplied `trustChain`, creation needs no discovery; with one, provide pinned `trustAnchors` for its validation. Endpoint authorization is checked by the receiving wallet against the effective federation metadata during completion ([§7.1.1](https://openid.net/specs/openid-federation-wallet-1_0-05.html#section-7.1.1)). The application's OpenID4VP engine handles request delivery and response processing, including encryption for `direct_post.jwt`.

When `transaction_data` is present, creation checks its structure, credential references, and the SD-JWT holder-binding requirement before signing. `AuthorizationRequestCreationOptions.scopeQuery` supplies the application's DCQL mapping for a signed `scope`. This mapping is required for scope-based transaction requests unless a validated supplied chain provides a superior query override. Inline `dcql_query` takes precedence over this local mapping. The mapping stays local; the signed request retains its `scope` and original encoded transaction strings. Scope-based creation without transaction data needs no mapping.

Creation requires `state` when a known active query sets `require_cryptographic_holder_binding: false`, except for `dc_api` and `dc_api.jwt` ([OpenID4VP §5.3](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.3)). It checks the superior override, inline query, or supplied scope mapping. For an opaque scope without a mapping, the application must enforce this condition. The application generates fresh state with at least 128 bits of entropy, binds it to the session, and checks the returned value.

The SD-JWT check prevents the helper from signing requests the receiving wallet must reject under [OpenID4VP Appendix B.3.3](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.3.3). The local mapping requirement is an oidfed API contract: the application must supply the query corresponding to its scope. Creation uses effective superior queries when available from the validated supplied chain; otherwise it checks the inline or mapped query. The receiving wallet applies its own federation evidence and application checks. The `verifyTransactionData` and `queryPolicy` callbacks run during completion.

Authorization Request `redirect_uri` and `response_uri` values must be fragment-free, including an empty trailing `#` ([RFC 6749 §3.1.2](https://www.rfc-editor.org/rfc/rfc6749.html#section-3.1.2), [OpenID4VP §8.2](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.2)). The same rule applies to registered `response_uris`. Query strings and percent-encoded `%23` remain valid.

Registered `redirect_uris` can contain fragments for redirects returned after a direct-post response; [OpenID4VP §8.2](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.2) permits a random value in that fragment. Request Object URLs can also contain fragment hashes, as recommended by [OpenID Connect Registration §2](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata). Endpoint authorization compares the complete registered strings exactly.

Metadata fields that require HTTPS, including endpoint and key-reference URLs, reject userinfo and empty `@` delimiters. This adopts the receiver rejection policy recommended by [RFC 9110 §4.2.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-4.2.4); that section also prohibits senders from generating HTTP(S) target or field URIs containing userinfo. The same check applies to response and redirect URIs in Authorization Requests.

## Check federation-backed presentation requests

```ts
const prepared = await CredentialVerifierRole.prepareAuthorizationRequest(
  {
    client_id: outerClientId,
    request_uri: requestObjectUri,
    request_uri_method: "post",
  },
  trustAnchors,
);
if (!prepared.ok) throw new Error(prepared.error.description);

// The application's OpenID4VP engine performs the authorized GET or POST.
const requestUri = prepared.value.requestUri;
if (!requestUri) throw new Error("Prepared Request Object URI is missing");
const jwt = await vpEngine.retrieveRequestObject(requestUri, walletNonce);
const checked = await CredentialVerifierRole.completeAuthorizationRequest(
  prepared.value,
  jwt,
  { walletNonce },
);
if (!checked.ok) throw new Error(checked.error.description);

await vpEngine.processFederatedRequest(
  checked.value.request,
  checked.value.effectiveQueries,
  { querySource: checked.value.querySource, metadata: checked.value.verifierMetadata },
);
```

`maxRequestAgeSeconds` is an optional wallet freshness policy. When set, completion requires `iat` within the configured window and clock-skew tolerance. Supplied expiry and activation claims retain [RFC 7519 semantics](https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.4). Request creation rejects invalid dates, expired output, and an empty `nbf`/`exp` interval. Completion rechecks expiry after callbacks; retained redirect validation also observes the request's applicable expiry and age limit.

Preparation checks the federation chain, effective signing keys, and registered Request Object endpoint. It returns an opaque preparation handle, not a fully validated chain. Completion checks the signed object, its type, the full prefixed client identifier, applicable wallet nonce, audience, endpoints, and pending DCQL policies. It rejects expired or cancelled preparation.

By default, the expected Request Object audience is `https://self-issued.me/v2` for static wallet discovery. Set `walletIssuer` for dynamic discovery. An optional Request Object `iss` is ignored according to OpenID4VP. Protocol parameters come from the signed object; outer request parameters cannot override them. For inline delivery, supply `request` during preparation and complete with that same JWT. Preparation rejects an incorrect JWT type before using its discovery hints.

The application's transport must enforce OpenID4VP's GET/POST rules, response media type, and HTTP-error handling. It must perform session binding and any remaining protocol checks. Requests with transaction data require a `verifyTransactionData` callback to validate the transaction type and its contents after the library's request checks pass. Credential selection, selective disclosure, presentation verification, and actual Holder Binding remain protocol-engine responsibilities.

Before invoking `verifyTransactionData`, the library checks that every [transaction credential ID](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.1) belongs to the active presentation query. The callback's `queries` contains the signed request query or the application's `scopeQuery` mapping; when superior metadata overrides the request, it contains that effective list. The published authorization list remains available through `effectiveQueries` and `queryPolicy`. DCQL [claim sets](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1) may include an empty alternative to request no selectively disclosable claims.

Completion rejects transaction data referencing a `dc+sd-jwt` query with `require_cryptographic_holder_binding: false`, as required by [Appendix B.3.3](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.3.3). An omitted flag defaults to `true` ([§6.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1)). Unrelated queries may disable binding. When separate superior scenarios reuse a credential ID, oidfed checks every matching definition, so a binding-disabled SD-JWT match causes rejection regardless of scenario order.

The original encoded transaction strings remain available in `request.transaction_data`; the callback receives decoded objects with their extension fields. The protocol engine must construct and verify the required cryptographic bindings, including hashes over the original encoded strings when using the profile in [Appendix B.3.3.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.3.3.1).

Only registered request, response, and redirect endpoints are allowed. After `direct_post`, check a Response Endpoint's returned redirect before following it:

```ts
const redirect = CredentialVerifierRole.validateResponseRedirect(
  checked.value,
  responseRedirectUri,
);
if (!redirect.ok) throw new Error(redirect.error.description);
```

DCQL processing follows Wallet Draft 05 §7.1.1. A superior-provided metadata list overrides request queries. Otherwise, metadata policies apply to the verifier's published queries, or to `client_metadata.dcql_query` when those queries are absent. The latter is implemented as a narrow wallet-profile exception to OpenID4VP's general instruction to ignore `client_metadata` for `openid_federation`. This is an interpretation of the two texts; it does not permit request-supplied keys or endpoints.

`effectiveQueries` contains the policy-processed federation query list when available, or the validated request query otherwise. `querySource` identifies superior metadata, verifier metadata, metadata policy, or the request. The returned `request` and the `queryPolicy` callback receive the same sanitized fields: `client_metadata` is always removed; a superior metadata override also removes `dcql_query`, `dcql_queries`, and `scope`.

Removing the plural request field is a defensive library choice. [Wallet Draft 05 §7.1.1](https://openid.net/specs/openid-federation-wallet-1_0-05.html#section-7.1.1) explicitly requires ignoring the singular `dcql_query`, while [§11.1.1](https://openid.net/specs/openid-federation-wallet-1_0-05.html#section-11.1.1) registers `dcql_queries` for authorization requests without defining its evaluation. Without a superior override, the library preserves the plural field as an uninterpreted extension. It never uses that field to compute `effectiveQueries` or satisfy OpenID4VP's [requirement for `dcql_query` or `scope`](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.1).

For received DCQL, completion ignores later claim queries with the same path, following [OpenID4VP §6.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1). It keeps the first claim’s constraints and redirects references in `claim_sets` to that claim, preserving alternative order and empty alternatives. Federation policies run on the original input before this normalization. Creation and metadata publication still reject duplicate paths.

A leaf-published scenario list remains separate from the selected signed query. Without a superior override, completion validates that query even when metadata lists authorized scenarios. Scope-based requests require the application's mapped `scopeQuery` at completion. Bind that mapping to the verified request’s scope before acting on the result; the API accepts the mapped query as an object. The protocol engine must apply the authorization context when selecting credentials. An optional `queryPolicy` callback enforces framework restrictions using the selected request and the effective list. For example, a framework can require an inline query to equal one authorized scenario, using structural JSON equality, or permit a defined refinement. A policy-approved contextual query does not by itself authorize a different active query. [Wallet §6.3.1](https://openid.net/specs/openid-federation-wallet-1_0-05.html#section-6.3.1) leaves this profile choice to the framework; configure the callback or enforce it in the protocol engine before releasing credentials.

For an inline-only application profile, this callback requires a federation-supplied scenario list and an exact match. `sameJson` is the application's structural JSON comparator: object property order is irrelevant and array order is preserved. Handle mapped scopes and superior overrides according to your profile if you support them.

```ts
queryPolicy: ({ request, queries, chain }) =>
  Array.isArray(chain.resolvedMetadata.openid_credential_verifier?.dcql_queries) &&
  request.dcql_query !== undefined &&
  queries.some((allowed) => sameJson(allowed, request.dcql_query))
```

## Integrate credential and alternative-attestation formats

`CredentialVerifierRole.verifyCredential(credential, issuerId, trustAnchors, options)` validates issuer trust, resolves applicable published keys, then invokes the required `verifyCredential` callback. The callback receives the credential, trusted issuer evidence, available protocol keys, and a cancellation signal. It must verify the format, cryptographic bindings, status, and applicable framework policy. Without a published key representation, `keys` is undefined and the configured verifier must use another trusted verification method or reject the credential, consistent with [Wallet Draft 05 §4](https://openid.net/specs/openid-federation-wallet-1_0-05.html#section-4).

`CredentialIssuerRole.verifyProviderAttestation` and `CredentialVerifierRole.verifyProviderAttestation` support other attestation formats through a required `verifyAttestation` callback. They validate provider trust and resolve protocol keys from effective provider metadata before calling it. The supported representations are `jwks`, `jwks_uri`, and `signed_jwks_uri`. Missing keys or a resolution failure returns an error without invoking the callback. Provider discovery remains available without published protocol keys.

The callback receives the attestation, trusted provider evidence, a required `keys` JWK Set, and a cancellation signal. It must cryptographically verify the attestation using those keys and apply its format and framework checks before returning `true`. [Wallet Draft 05 §8.5](https://openid.net/specs/openid-federation-wallet-1_0-05.html#section-8.5) requires verification using cryptographic material provided by the federation Trust Chain; the key representations above are oidfed's supported mechanism. The application implements the format-specific verification. These helpers establish Wallet Provider trust; a Verifier Instance attestation profile under [Wallet §8.1](https://openid.net/specs/openid-federation-wallet-1_0-05.html#section-8.1) needs its own issuer, format, and validation rules.

For both credential and attestation callbacks, missing callbacks, rejection, exceptions, timeout, and cancellation prevent acceptance. Callback inputs are detached copies, and issuer/provider trust evidence must remain unexpired when verification finishes.

VCI protocol endpoints and optional signed issuer metadata/proofs retain their own processing rules. In particular, a VCI JWT proof using `trust_chain` for signature verification requires `kid`, unlike a generic attestation PoP JWT. Passing federation validation does not establish that a presentation, proof, or credential is valid.

Offline validation depends on the age of the supplied evidence. It does not prove current non-revocation after that evidence was issued. Frameworks choose chain lifetimes and revalidation schedules; the draft's 24-hour example is not a fixed library limit.
