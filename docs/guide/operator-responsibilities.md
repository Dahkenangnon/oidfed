# Operator and application responsibilities

oidfed validates federation evidence and provides [composable entity roles](../README.md#integration-model). Your application runs the protocol engine and connects storage and key providers. These package and adapter boundaries are oidfed design choices.

| Owner | Responsibilities |
|---|---|
| Federation operator | Trusted anchors, enrollment policy, accepted Trust Marks, authentication policy, rollover timing, and any framework-specific revocation process. |
| Application integrator | HTTP serving, protocol engines, sessions, registration expiry, verification callbacks, and scheduled work. |
| Storage or key adapter implementer | Persistence, namespace isolation, atomic operations, transaction guarantees, and key custody behind the injected contracts. |

One team may fill several roles. When oidfed delegates a required check to your application, you still need to implement it. The keywords **MUST**, **SHOULD**, **RECOMMENDED**, and **MAY** retain their specification meanings. Library contracts and deployment advice are labelled separately.

Federation section numbers refer to [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html). The two split 1.1 specifications cover the same functionality, as explained in [§17.6](https://openid.net/specs/openid-federation-1_0.html#section-17.6). See the [support table](../../README.md#implemented-specifications-and-features) for implemented specifications and drafts.

## Shared storage and key contracts

The authority's [`StorageAdapter`](../../packages/authority/src/storage/types.ts) stores subordinate records and any configured Trust Mark, event, collection, replay, and cache data. Configure OIDC registrations and sessions, wallet protocol state, and role-specific replay stores through their [OIDC](../packages/oidc.md#oidcproviderroleconfig-and-oauthauthorizationserverroleconfig) and [wallet](../packages/wallet.md#sign-and-verify-wallet-attestations) integration points. Attaching a role to a host does not connect all of that role's state to authority storage.

Production adapters must meet oidfed's [storage contracts](storage-guide.md): isolate authority namespaces, return detached records, and provide serializable transactions with atomic commit and rollback. The transaction API and these adapter guarantees are library contracts. The specifications do not prescribe a database technology.

Client assertions require `exp`, `jti`, and one-time use unless reuse was negotiated. These requirements come from [OIDC Core §9](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication), referenced by [Federation §8.8](https://openid.net/specs/openid-federation-1_0.html#section-8.8). oidfed enforces one-time use through its [replay contract](storage-guide.md#replay-protection). The store must claim identifiers atomically across processes serving the same receiver, retain them through the accepted expiry and clock-skew window, and fail closed on backend errors. This store design is an oidfed contract.

Under oidfed's [key-provider contract](../packages/core.md#federation-key-providers), the provider is responsible for private-key custody and lifecycle state. Production providers must persist that state and coordinate the processes signing and publishing for one entity. Lifecycle providers retain historical public keys separately from the current JWKS.

Publishing a Historical Keys endpoint is optional under [Federation §8.7](https://openid.net/specs/openid-federation-1_0.html#section-8.7). If you publish one, its response and historical-key fields follow [§8.7.2](https://openid.net/specs/openid-federation-1_0.html#section-8.7.2). The bundled [memory key provider](../../packages/core/src/federation-keys.ts) and memory stores lose state on restart and do not coordinate across processes.

Federation Entity Keys **SHOULD NOT** be used for other protocols under [Federation §3.1.1](https://openid.net/specs/openid-federation-1_0.html#section-3.1.1). [§5.2.1](https://openid.net/specs/openid-federation-1_0.html#section-5.2.1) separates protocol-role keys from top-level federation keys. If you publish multiple protocol JWK Set representations, [§5.2.1.1](https://openid.net/specs/openid-federation-1_0.html#section-5.2.1.1) says their keys **SHOULD** be the same and implementations **MUST** make them consistent in a timely manner.

oidfed provides separate federation key providers and protocol signers. Your application manages protocol-key rotation and publication. OIDC's [`ProtocolSigningKeyProvider`](../../packages/oidc/src/protocol-keys.ts) and wallet operations accepting [`JwtSigner`](../packages/wallet.md#sign-and-verify-wallet-attestations) do not implement the publication, switching, or retirement lifecycle of `FederationKeyLifecycleProvider`.

## OpenID Federation

### Trusted anchors and independent key retrieval

[Federation §10](https://openid.net/specs/openid-federation-1_0.html#section-10) requires the target's identifier, trusted anchor identifiers, and the anchors' public signing keys before establishing trust. [§10.2](https://openid.net/specs/openid-federation-1_0.html#section-10.2) requires validation against the anchor's public key. The operator supplies these inputs through [`TrustAnchorSet`](../../packages/core/src/types.ts). Discovery and collection results do not add anchors to that set.

[§11.3](https://openid.net/specs/openid-federation-1_0.html#section-11.3) says an independent source of Trust Anchor public keys is **RECOMMENDED**. Those keys **SHOULD** be compared with the Entity Configuration keys. If they differ, both sets **SHOULD** be retrieved again. The operator **SHOULD** define how to handle a persistent mismatch.

Core's [`compareTrustAnchorKeys(ecJwks, independentJwks, entityId)`](../../packages/core/src/trust-chain/anchor-keys.ts) compares supplied key identifiers and JWK thumbprints. The operator chooses the independent source and mismatch policy under [§11.3](https://openid.net/specs/openid-federation-1_0.html#section-11.3). Your application retrieves the keys and runs the comparisons; the function makes no network requests or automatic corrections. The specification sets no fixed comparison schedule.

### Rollover, freshness, and revocation

Use oidfed's [federation key contracts](../packages/core.md#federation-key-providers) to publish keys, switch signers, retire keys, and retrieve historical keys. For a Trust Anchor, the application drives the four stages in [§11.2](https://openid.net/specs/openid-federation-1_0.html#section-11.2):

1. Publish the new public keys.
2. Keep signing with the old keys while participants obtain the new ones.
3. Switch to signing with the new keys.
4. Remove the old keys after a suitable overlap.

More generally, [§11.1](https://openid.net/specs/openid-federation-1_0.html#section-11.1) uses Entity Configuration expiry to control when participants retrieve updated federation keys.

[§11.2](https://openid.net/specs/openid-federation-1_0.html#section-11.2) leaves overlap timing to the Trust Anchor's security profile and risk assessment. The operator chooses Entity Configuration lifetimes, how long to wait before switching, and how long to retain the old keys afterward. The memory provider's seven-day post-switch overlap is an [oidfed default](../packages/authority.md#federation-key-rotation). The specification prescribes no such duration, and this setting does not control the pre-switch wait.

A Leaf [caches its Entity Configuration](../packages/leaf.md#how-does-the-entity-configuration-caching-work). Call `refreshEntityConfiguration()` when changed keys or a new signer need to be published before the cached JWT expires. As deployment guidance, account for proxy caches when choosing publication timing.

[§11](https://openid.net/specs/openid-federation-1_0.html#section-11) requires participants to support refreshing expired Trust Chains. A chain expires with its earliest-expiring statement under [§10.4](https://openid.net/specs/openid-federation-1_0.html#section-10.4), and [§10.2](https://openid.net/specs/openid-federation-1_0.html#section-10.2) requires checking statement times. Core checks these times during [chain validation](../packages/core.md#trust-chain-discovery-and-validation). Your application must reevaluate trust before continuing to rely on expired evidence. oidfed does not schedule reevaluation of trust decisions retained by applications.

[§11.4](https://openid.net/specs/openid-federation-1_0.html#section-11.4) defines no federation-wide revocation process; a federation **MAY** define its own. In oidfed, [`revokeKey()`](../../packages/core/src/federation-keys.ts) changes local provider state and historical records. [`revokeSubordinate()`](../../packages/authority/src/subordinate-lifecycle.ts) removes the current registration. Neither invalidates statements cached elsewhere, and [§10.2](https://openid.net/specs/openid-federation-1_0.html#section-10.2) permits caching until expiry.

The operator defines any additional federation revocation process. [Trust Mark Status](https://openid.net/specs/openid-federation-1_0.html#section-8.4) and [historical-key revocation fields](https://openid.net/specs/openid-federation-1_0.html#section-8.7.2) cover their respective objects; they do not define a general participant-revocation protocol.

### Endpoint access and network policy

[§8.8](https://openid.net/specs/openid-federation-1_0.html#section-8.8) lets a federation require, allow, or omit client authentication at federation endpoints. Its `private_key_jwt` assertions **MUST** use Federation Entity Keys and the receiver's Entity Identifier as audience. Authenticated requests **MUST** use POST. The operator selects per-endpoint `*_auth_methods` under [§8.8.1](https://openid.net/specs/openid-federation-1_0.html#section-8.8.1); the default is `["none"]`.

The specification also permits other authentication methods. oidfed's [authority middleware](../../packages/authority/src/endpoints/client-auth.ts) supports `none` and `private_key_jwt` and rejects unsupported configurations at construction. Configure `storage.replay` when using `private_key_jwt`. Other integrations configure their own stores under the [replay contract](storage-guide.md#replay-protection).

Entity Configuration discovery **MUST** use GET under [§9.1](https://openid.net/specs/openid-federation-1_0.html#section-9.1). [§9](https://openid.net/specs/openid-federation-1_0.html#section-9) sets publication requirements and Leaf exceptions. oidfed serves discovery without a Federation client assertion. The authentication metadata in [§8.8.1](https://openid.net/specs/openid-federation-1_0.html#section-8.8.1) covers the endpoints named in [§5.1.1](https://openid.net/specs/openid-federation-1_0.html#section-5.1.1); it does not configure discovery access controls. See the [HTTP discovery contract](../packages/core.md#http-discovery-and-fetching).

Your application serves the HTTPS endpoints required by [§5.1.1](https://openid.net/specs/openid-federation-1_0.html#section-5.1.1) and [§9](https://openid.net/specs/openid-federation-1_0.html#section-9). [§18.1](https://openid.net/specs/openid-federation-1_0.html#section-18.1) describes HTTP propagation attacks and the need for defenses. Core provides URL checks and bounded reads under its [HTTP contract](../packages/core.md#http-discovery-and-fetching). DNS resolution and redirect handling also depend on the injected transport. Choose outbound access controls for your deployment; §18.1 does not mandate a particular network-filtering algorithm.

The operator sets framework eligibility rules. Available mechanisms include the metadata policies permitted by [§6.1](https://openid.net/specs/openid-federation-1_0.html#section-6.1) and the Trust Mark issuer/owner declarations defined in [§3.1.2](https://openid.net/specs/openid-federation-1_0.html#section-3.1.2). [§17.5](https://openid.net/specs/openid-federation-1_0.html#section-17.5) separates validating a mark from deciding whether to use it. oidfed applies configured policies and verifies evidence; the framework defines acceptance criteria. Application-specific metadata value types **SHOULD** be checked after resolution under [§6.1](https://openid.net/specs/openid-federation-1_0.html#section-6.1).

## OIDC federation

`@oidfed/oidc` creates and validates the federation registration artifacts defined in [Federation §12.1](https://openid.net/specs/openid-federation-1_0.html#section-12.1) and [§12.2](https://openid.net/specs/openid-federation-1_0.html#section-12.2). Under oidfed's [integration boundary](../packages/oidc.md), your OP/RP implementation handles authentication, tokens, sessions, registration persistence, and client-secret custody. Role hooks pass accepted registrations to that implementation. Authority storage does not provide an OIDC client database.

[Federation §12.3](https://openid.net/specs/openid-federation-1_0.html#section-12.3) sets two lifetime limits:

- An OP registration **MUST NOT** outlive the RP Trust Chain used to establish it. The OP may expire it earlier or reevaluate it periodically.
- An RP **MUST NOT** use a registration past the OP Trust Chain's expiry. Before continuing, an automatically registered RP must successfully reevaluate OP trust; an explicitly registered RP must successfully renew registration.

The [explicit-registration handler](../../packages/oidc/src/registration/handler.ts) caps registration expiry to the selected RP chain under [§12.2.2](https://openid.net/specs/openid-federation-1_0.html#section-12.2.2) and includes that expiry in the signed response under [§12.2.3](https://openid.net/specs/openid-federation-1_0.html#section-12.2.3). [OP-side automatic processing](../../packages/oidc/src/registration/process-automatic.ts) returns `ProcessedRegistration.trustChain`. [RP-side automatic registration](../packages/oidc.md#automatic-registration-result) returns the OP chain and `trustChainExpiresAt`.

To meet [§12.3](https://openid.net/specs/openid-federation-1_0.html#section-12.3), retain these validated deadlines and enforce them when processing registrations and requests. For explicit registration, also retain the selected OP chain's expiry alongside the returned registration limits. A response JWT's expiry does not enforce your client record's lifetime by itself.

[`onRegistration`](../../packages/oidc/src/roles.ts) receives client metadata and an optional secret, but no chain deadline. To enforce [§12.3](https://openid.net/specs/openid-federation-1_0.html#section-12.3), your protocol integration must also associate each registration with the evidence and expiry used to establish trust.

[§12.1.1.1](https://openid.net/specs/openid-federation-1_0.html#section-12.1.1.1) defines one-time use of automatic-registration Request Objects, with an exception for negotiated reuse. oidfed's OP role enforces one-time use through its own configured `ReplayStore`; it does not inherit the host's store. Your application also manages protocol-key rotation and publication under the [OIDC integration contracts](../packages/oidc.md#common-questions).

## Extended Listing, Draft 03

The authority handler implements the `from` and claim-selection rules in [§3.2](https://openid.net/specs/openid-federation-extended-listing-1_0-03.html#section-3.2) and the opaque `next` pointer in [§3.3](https://openid.net/specs/openid-federation-extended-listing-1_0-03.html#section-3.3). Responses **MUST** use consistent ordering under [§3.1.1](https://openid.net/specs/openid-federation-extended-listing-1_0-03.html#section-3.1.1). Implementations choose the ordering key. oidfed's [storage contract](storage-guide.md#subordinates) uses lexicographic Entity Identifier ordering and an inclusive first-unreturned cursor.

The time filters in [§3.2](https://openid.net/specs/openid-federation-extended-listing-1_0-03.html#section-3.2) and audit fields in [§3.3](https://openid.net/specs/openid-federation-extended-listing-1_0-03.html#section-3.3) need accurate registration and update times. oidfed's adapter contract requires maintaining those timestamps and applying repository filters before pagination. Repeated Trust Mark types use OR matching, as required by §3.2. Direct writes must supply or maintain the fields required by the [subordinate storage contract](storage-guide.md#subordinates).

Choose limits that allow the endpoint to return the requested claims, following [§3.1.2](https://openid.net/specs/openid-federation-extended-listing-1_0-03.html#section-3.1.2). Configure authentication through the endpoint's advertised methods. [§3.2](https://openid.net/specs/openid-federation-extended-listing-1_0-03.html#section-3.2) uses the base List endpoint's authentication rules.

[Federation §8.2.1](https://openid.net/specs/openid-federation-1_0.html#section-8.2.1) defines the `trust_marked=true` filter and leaves the false case unspecified. As library policy, oidfed treats `false` as adding no restriction. Supplied mark-type filters still apply. See the [Extended Listing configuration](../packages/authority.md#extended-subordinate-listing) for optional features and defaults.

## Subordinate Events, Draft 01

The endpoint is optional for Trust Anchors and Intermediates under [§2.1](https://openid.net/specs/openid-federation-subordinate-events-1_0-01.html#section-2.1). [§2.1.1](https://openid.net/specs/openid-federation-subordinate-events-1_0-01.html#section-2.1.1) defines how to advertise it in metadata, and [§2.3.1](https://openid.net/specs/openid-federation-subordinate-events-1_0-01.html#section-2.3.1) specifies a history JWT signed with a Federation Entity Key.

When event storage is enabled, oidfed's [lifecycle methods](../../packages/authority/src/subordinate-lifecycle.ts) capture registration, changes to attested metadata and policies, registered key changes, and explicit revocation. Production adapters commit each mutation and its generated events together under the [event storage contract](storage-guide.md#subordinate-events).

Direct writes to `storage.subordinates` bypass automatic capture. Under the [capture contract](storage-guide.md#subordinate-events), applications must append events in the same transaction if those changes belong in the published history. Enabling storage does not reconstruct past events from timestamps.

oidfed requires history to survive removal and prohibits silent pruning or truncation. The draft's [response format](https://openid.net/specs/openid-federation-subordinate-events-1_0-01.html#section-2.3) defines event data but prescribes no retention duration, database, or transaction mechanism.

[§2.3.3](https://openid.net/specs/openid-federation-subordinate-events-1_0-01.html#section-2.3.3) defines `suspension` as a suspended registration and `revocation` as a revoked registration. Custom event types **MAY** be defined and **SHOULD** be documented by the framework or operator. The operator defines the administrative process behind these events; their names already have specification-defined meanings.

oidfed's [`recordSubordinateEvents()`](../../packages/authority/src/subordinate-lifecycle.ts) records observations without changing registration state. Your application enforces suspension. `revokeSubordinate()` removes the current registration and records revocation. Record revocation only when removal reflects that decision; technical cleanup alone does not.

The response reports the issuer's view of events under [§2.3.1](https://openid.net/specs/openid-federation-subordinate-events-1_0-01.html#section-2.3.1). Its signature alone does not prove that the chain-validation checks in [Federation §10.2](https://openid.net/specs/openid-federation-1_0.html#section-10.2) passed at an earlier time. The draft defines a retrieval endpoint and provides no notification protocol. See [subordinate event history](../packages/authority.md#subordinate-event-history) for oidfed's capture boundaries and lookup policies.

## Entity Collection, Draft 01

[§5.1](https://openid.net/specs/openid-federation-entity-collection-1_0-01.html#section-5.1) and [§5.3](https://openid.net/specs/openid-federation-entity-collection-1_0-01.html#section-5.3) leave collection methods and additional scope restrictions to implementations. The operator selects supported anchors and scope. Under [§5.2](https://openid.net/specs/openid-federation-entity-collection-1_0-01.html#section-5.2), implementations **SHOULD** consider Entity Configuration information when populating response claims and **MAY** use additional information.

oidfed's default collector validates chains against pinned anchors. To use other sources or impose additional restrictions, provide a custom collector or refresh-time filter under the [collection policy contract](entity-collection.md#collection-policy). Custom collectors manage their input sources and eligibility deadlines.

[`EntityCollectionService`](../../packages/core/src/entity-collection/service.ts) serves stored snapshots. Your application schedules `refresh()`; requests do not start traversal. The service serializes refreshes for each anchor within one instance. The [store contract](../../packages/core/src/entity-collection/types.ts) requires atomic publication but does not serialize refresh work across processes.

If multiple writers need ordered publication, choose a coordination mechanism, such as one scheduled writer per anchor or an external lock. [§5.1](https://openid.net/specs/openid-federation-entity-collection-1_0-01.html#section-5.1) leaves the implementation open. It does not prescribe snapshots, a refresh interval, or a distributed scheduler.

Responses **MUST** use consistent ordering under [§3.1.1](https://openid.net/specs/openid-federation-entity-collection-1_0-01.html#section-3.1.1). [§3.3.1](https://openid.net/specs/openid-federation-entity-collection-1_0-01.html#section-3.3.1) defines continuation requests and unavailable cursors. oidfed's [refresh and storage contract](entity-collection.md#refresh-and-storage) requires storage implementers to provide atomic publication, anchor isolation, detached reads, and snapshot/cursor retention.

oidfed keeps the previous snapshot after an incomplete refresh and bounds optional issuer lookups as part of its availability policy. Operators choose refresh frequency. Monitoring failures and snapshot age is deployment guidance.

Authentication follows [§3.3.1](https://openid.net/specs/openid-federation-entity-collection-1_0-01.html#section-3.3.1) and [Federation §8.8](https://openid.net/specs/openid-federation-1_0.html#section-8.8). The configured replay store and memory fallback are [oidfed integration choices](entity-collection.md#authentication-and-http-clients). The memory store does not protect against replay across processes.

[§6.1](https://openid.net/specs/openid-federation-entity-collection-1_0-01.html#section-6.1) requires clients to treat unsigned results as informational and returned Trust Marks as unverified. Perform federation trust validation of selected entities and verify marks before relying on them, even if the collector checked them during refresh.

## Wallet Federation, Draft 05

`@oidfed/wallet` provides wallet roles with federation support, including the effective-metadata and endpoint checks in [Wallet §7.1.1](https://openid.net/specs/openid-federation-wallet-1_0-05.html#section-7.1.1). You supply the OpenID4VCI/OpenID4VP protocol engine, as described in the [package guide](../packages/wallet.md). [Wallet §10](https://openid.net/specs/openid-federation-wallet-1_0-05.html#section-10) applies those protocols' security considerations too. Federation validation does not replace their processing rules.

[Wallet §4](https://openid.net/specs/openid-federation-wallet-1_0-05.html#section-4) requires Credential Verifiers to be able to verify credentials using issuer keys or another verification method. [OpenID4VP §8.6](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6) requires checks for format-specific integrity, authenticity, query matching, applicable Holder Binding, and framework policy. It gives revocation checks as a policy-dependent example. Verifiers **MUST NOT** rely on the Wallet to enforce their constraints under [§14.9](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-14.9).

oidfed validates issuer trust and passes available protocol keys to the required `verifyCredential` callback. Your application verifies credential formats, cryptographic bindings, and any status checks required by its format or framework. Use `verifyAttestation` for alternative attestation formats under the [format callback contracts](../packages/wallet.md#integrate-credential-and-alternative-attestation-formats), and `acceptWallet` for [wallet acceptance](../packages/wallet.md#sign-and-verify-wallet-attestations). These are oidfed integration points. Return success only after the required verification; federation trust alone does not prove a credential or presentation valid.

The JWT Wallet Attestation format and PoP usage come from [OpenID4VCI Appendix E](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-E) and its referenced OAuth Attestation Client Authentication Draft 07. For header-based authentication, check that exactly one attestation field and one PoP field each contain one well-formed JWT, as required by [OAuth Draft 07 §9](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-07.html#section-9). Pass that pair to oidfed for validation.

[§12.1](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-07.html#section-12.1) describes freshness and replay defenses. oidfed uses a configurable 300-second PoP window and requires a caller-supplied replay store. Those choices are [library policies](../packages/wallet.md#sign-and-verify-wallet-attestations).

For presentation requests delivered by reference, your application's transport retrieves the Request Object under [OpenID4VP §5.10](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.10). It must enforce the [response media type](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.10.1) and [HTTP-error handling](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.10.2). oidfed validates the retrieved signed object through its [prepare/complete API](../packages/wallet.md#check-federation-backed-presentation-requests).

Your application handles session binding and the applicable defenses in [§14.2](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-14.2) and [§14.3](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-14.3). It also processes presentations under [§8.6](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6).

For scope-based queries, supply oidfed's `scopeQuery` mapping using the alias rules in [OpenID4VP §5.5](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.5). Transaction-data processing follows [§5.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.1) and [§8.4](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.4). oidfed rejects unsupported transaction data unless your `verifyTransactionData` callback validates it. See the [presentation-request integration contract](../packages/wallet.md#check-federation-backed-presentation-requests).

[Wallet §8.2](https://openid.net/specs/openid-federation-wallet-1_0-05.html#section-8.2) says wallets **SHOULD** periodically reestablish trust with their providers. Your application chooses and runs that schedule.

For offline flows, [§9](https://openid.net/specs/openid-federation-wallet-1_0-05.html#section-9) explains how to validate supplied chains with anchor keys and relates chain lifetimes to framework revocation requirements. Its 24-hour example is not a fixed limit. The operator sets acceptable evidence lifetimes. Your application supplies pinned keys, chains, and protocol keys. oidfed's [`offline: true`](../../packages/wallet/src/trust.ts) blocks library network calls; your callbacks must also work offline. Offline validation does not prove that federation standing is still current.

## Deployment operations

The following are deployment recommendations. The linked sections explain the protocol concerns behind them. They do not prescribe backup systems, monitoring tools, or clock-synchronization services.

- Restrict access to private keys, registration secrets, and administrative mutation paths. [Federation §3.1.1](https://openid.net/specs/openid-federation-1_0.html#section-3.1.1) defines published federation JWKS as public keys. Follow oidfed's [key custody contract](storage-guide.md#keys): keep private material behind the provider and out of authority records and published metadata.
- Back up authoritative storage and key-provider state. Test recovery of historical public keys, event histories, registration deadlines, and replay state without allowing accepted proofs to be replayed. Plan recovery around oidfed's [storage guarantees](storage-guide.md); the specifications define no backup protocol.
- Synchronize clocks across serving processes. [Federation §10.2](https://openid.net/specs/openid-federation-1_0.html#section-10.2) requires time checks; [JWT §4.1.4](https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.4) permits small leeway for clock skew. Account for the configured acceptance window when retaining replay records and scheduling expiry and rollover.
- Monitor refresh failures, snapshot age, signing failures, replay-store errors, and expiring evidence using oidfed's [refresh](entity-collection.md#refresh-and-storage) and [replay](storage-guide.md#replay-protection) contracts. Follow [Federation §11.3](https://openid.net/specs/openid-federation-1_0.html#section-11.3) when handling persistent independent-key mismatches. Choose alert thresholds for your deployment.
- Define how to respond to key compromise and loss of authoritative state, including recovery procedures. The framework chooses any additional federation revocation process under [§11.4](https://openid.net/specs/openid-federation-1_0.html#section-11.4).
- Limit published Entity Statements to organizational information needed for federation, following [§19.1](https://openid.net/specs/openid-federation-1_0.html#section-19.1). Consider the tracking risks of Trust Mark Status and Fetch requests and the mitigations discussed in [§19.2](https://openid.net/specs/openid-federation-1_0.html#section-19.2) and [§19.3](https://openid.net/specs/openid-federation-1_0.html#section-19.3).
