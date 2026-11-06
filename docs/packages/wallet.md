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

Hosts compose role metadata with their own metadata, then call the optional `EntityRole.validateMetadata` hook before publication. Role configuration takes precedence over fields supplied by the host. Wallet roles validate the composed block, including exact equality between `credential_issuer` and the host's Entity Identifier.

The provider and verifier metadata require `vp_formats_supported`. Issuers require `credential_issuer`, `credential_endpoint`, and `credential_configurations_supported`, with the nested requirements from OpenID4VCI. Metadata extensions are preserved. The three roles expose `parseMetadata(value)` for validation without a host.

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

Discovery returns effective role metadata and a validated trust chain. Issuer discovery also validates the federation identities of the listed authorization servers. When `authorization_servers` is absent, it uses the issuer itself and requires its `oauth_authorization_server` metadata.

Use existing List or Entity Collection APIs to find candidates, then discover each selected issuer independently. Collection data is informational. Applications choose when to repeat provider discovery to check current federation standing.

Discovery and verification accept core's HTTP client, clock, cancellation signal, cache, timeout, response-size limit, and fetch limits. Each operation shares its fetch budget across participant discovery, authorization-server discovery, and protocol-key retrieval. The default is 50 network calls.

`trustChain` supplies a preconstructed chain for the target. `entityChains` supplies additional chains keyed by subject. Every supplied chain is checked against the caller's pinned anchors. `offline: true` blocks library network requests. Supply the chains and protocol keys needed by the selected operation, and keep application verification callbacks offline too.

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

Protocol operations use a core `JwtSigner`. Their remote keys come from the effective role metadata through core's key resolver. Effective inline `jwks` takes precedence over URI representations so a superior's replacement set cannot be bypassed. Top-level federation keys are not substituted automatically. Wallet Draft 05 does not define a provider attestation-key field; publishing provider protocol keys as `jwks`, `jwks_uri`, or `signed_jwks_uri` is this integration's convention and must match the deployed framework.

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

The default PoP freshness window is 300 seconds, configurable through `maxProofAgeSeconds`. Core's clock-skew tolerance also applies. This duration and the required caller-supplied `ReplayStore` are library policies. The store must claim identifiers atomically and retain them through the acceptance window. Authentication rejects replay-store failures; `MemoryReplayStore` is available for development.

An attestation's `iat` and a PoP's `exp` are optional. A PoP still requires `iat` and `jti`. The formats do not require a JWT `kid`; usable trusted public keys remain necessary. Attestation subjects can be shared by a wallet implementation and must not be treated as unique federation identifiers.

The application parses any authentication headers. OAuth Draft 07 requires exactly one attestation field and one PoP field, each containing one well-formed JWT. Pass that validated pair to the authentication operation.

## Create a signed presentation request

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

The helper sets the `openid_federation:` client identifier and wallet audience, validates the request parameters, and signs with the supplied protocol signer. `direct_post` requires `response_uri` and prohibits `redirect_uri` in the Authorization Request ([OpenID4VP §8.2](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.2)). The same rules apply to [`direct_post.jwt`](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.3.1). A request cannot contain both URI parameters. The helper requires `redirect_uri` for `fragment` and accepts other response-mode names for application-defined processing.

Supplied response and redirect URIs must be HTTPS URLs, matching [Wallet Draft 05 §6.3.1](https://openid.net/specs/openid-federation-wallet-1_0-05.html#section-6.3.1). Invalid response parameters return `invalid_request` before signing or trust-chain preparation. Without a supplied `trustChain`, creation needs no discovery; with one, provide pinned `trustAnchors` for its validation. Endpoint authorization is checked by the receiving wallet against the effective federation metadata during completion ([§7.1.1](https://openid.net/specs/openid-federation-wallet-1_0-05.html#section-7.1.1)). The application's OpenID4VP engine handles request delivery and response processing, including encryption for `direct_post.jwt`.

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

Preparation checks the federation chain, effective signing keys, and registered Request Object endpoint. It returns an opaque preparation handle, not a fully validated chain. Completion checks the signed object, its type, the full prefixed client identifier, applicable wallet nonce, audience, endpoints, and pending DCQL policies. It rejects expired or cancelled preparation.

By default, the expected Request Object audience is `https://self-issued.me/v2` for static wallet discovery. Set `walletIssuer` for dynamic discovery. An optional Request Object `iss` is ignored according to OpenID4VP. Protocol parameters come from the signed object; outer request parameters cannot override them. For inline delivery, supply `request` during preparation and complete with that same JWT.

The application's transport must enforce OpenID4VP's GET/POST rules, response media type, and HTTP-error handling. It must perform session binding and any remaining protocol checks. Unsupported transaction data is rejected unless a `verifyTransactionData` callback validates it. Credential selection, selective disclosure, presentation verification, and Holder Binding remain protocol-engine responsibilities.

Before invoking `verifyTransactionData`, the library checks that every [transaction credential ID](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.1) belongs to the active presentation query. The callback's `queries` contains the signed request query or the application's `scopeQuery` mapping; when superior metadata overrides the request, it contains that effective list. The published authorization list remains available through `effectiveQueries` and `queryPolicy`. DCQL [claim sets](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1) may include an empty alternative to request no selectively disclosable claims.

Only registered request, response, and redirect endpoints are allowed. After `direct_post`, check a Response Endpoint's returned redirect before following it:

```ts
const redirect = CredentialVerifierRole.validateResponseRedirect(
  checked.value,
  responseRedirectUri,
);
if (!redirect.ok) throw new Error(redirect.error.description);
```

DCQL processing follows Wallet Draft 05 §7.1.1. A superior-provided metadata list overrides request queries. Otherwise, metadata policies apply to the verifier's published queries, or to `client_metadata.dcql_query` when those queries are absent. The latter is implemented as a narrow wallet-profile exception to OpenID4VP's general instruction to ignore `client_metadata` for `openid_federation`. This is an interpretation of the two texts; it does not permit request-supplied keys or endpoints.

`effectiveQueries` contains the policy-processed federation query list when available, or the validated request query otherwise. `querySource` identifies superior metadata, verifier metadata, metadata policy, or the request. The returned `request` always removes `client_metadata`. It removes `dcql_query` and `scope` only when superior metadata mandates overriding them. A leaf-published scenario list therefore remains separate from the selected signed query. Without a superior override, completion validates that query even when metadata lists authorized scenarios. Scope-based requests require the application's mapped `scopeQuery` at completion. The protocol engine must apply the authorization context when selecting credentials. An optional `queryPolicy` callback can enforce framework restrictions using the selected request and the effective list; the library does not invent semantic query-refinement rules.

## Integrate credential and alternative-attestation formats

`CredentialVerifierRole.verifyCredential(credential, issuerId, trustAnchors, options)` validates issuer trust, resolves applicable published keys, then invokes the required `verifyCredential` callback. The callback receives the credential, trusted issuer evidence, available protocol keys, and a cancellation signal. It must verify the format, cryptographic bindings, status, and applicable framework policy. Without a published key representation, `keys` is undefined and the configured verifier must use another trusted verification method or reject the credential, consistent with [Wallet Draft 05 §4](https://openid.net/specs/openid-federation-wallet-1_0-05.html#section-4).

`CredentialIssuerRole.verifyProviderAttestation` and `CredentialVerifierRole.verifyProviderAttestation` support other attestation formats through a required `verifyAttestation` callback. They validate provider trust and resolve protocol keys from effective provider metadata before calling it. The supported representations are `jwks`, `jwks_uri`, and `signed_jwks_uri`. Missing keys or a resolution failure returns an error without invoking the callback. Provider discovery remains available without published protocol keys.

The callback receives the attestation, trusted provider evidence, a required `keys` JWK Set, and a cancellation signal. It must cryptographically verify the attestation using those keys and apply its format and framework checks before returning `true`. [Wallet Draft 05 §8.5](https://openid.net/specs/openid-federation-wallet-1_0-05.html#section-8.5) requires verification using cryptographic material provided by the federation Trust Chain; the key representations above are oidfed's supported mechanism. The application implements the format-specific verification.

For both credential and attestation callbacks, missing callbacks, rejection, exceptions, timeout, and cancellation prevent acceptance. Callback inputs are detached copies, and issuer/provider trust evidence must remain unexpired when verification finishes.

VCI protocol endpoints and optional signed issuer metadata/proofs retain their own processing rules. In particular, a VCI JWT proof using `trust_chain` for signature verification requires `kid`, unlike a generic attestation PoP JWT. Passing federation validation does not establish that a presentation, proof, or credential is valid.

Offline validation depends on the age of the supplied evidence. It does not prove current non-revocation after that evidence was issued. Frameworks choose chain lifetimes and revalidation schedules; the draft's 24-hour example is not a fixed library limit.
