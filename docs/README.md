# Documentation

Use oidfed to establish federation trust around an existing application. Start with a feature guide when building a workflow; use the API reference when you need an exact option or return value.

**Before you configure oidfed**, confirm which rules apply to the participant you’ll represent and what its Immediate Superior requires for enrollment. [Confirm the federation’s requirements](features/1.federation-participants.md#confirm-the-federations-requirements).

| What you need | Start here |
|---|---|
| Enroll participants and operate a federation | [Federation participants](features/1.federation-participants.md) |
| Discover an entity and decide whether to trust it | [Trust chains](features/3.trust-chains.md) and [discovery](features/8.discovery.md) |
| Issue, publish, or rely on accreditation | [Trust Marks](features/6.trust-marks.md) |
| Connect an OP, RP, OAuth client, or authorization server | [OIDC and OAuth](features/15.oidc-and-oauth.md) |
| Add federation trust to a wallet ecosystem | [Wallet workflows](features/16.wallet.md) |
| Look up a function, class, option, or type | [API reference](api/README.md) |
| Upgrade an existing installation to v3 | [v3 migration guide](api/migration-v3.md) |

The [feature guides](features/README.md#shared-scenarios) use two examples. The academic federation from OpenID Federation Appendix A follows a researcher using the LIGO Wiki. The wallet guides follow a driving licence from issuance to presentation. Code examples use reserved `.example` addresses.

Choose one federation host per Entity Identifier: `Leaf`, `Intermediate`, or `TrustAnchor`. Compose protocol roles into it. The application supplies HTTPS serving, durable storage, key custody, and its OIDC/OAuth or wallet protocol engine. [Serve federation endpoints](features/11.5.http-wiring.md) connects the pieces.

## Package references

| Package | Public API |
|---|---|
| `@oidfed/crypto` | [Engines, signing custody, keyrings and compact JWS utilities](api/crypto/README.md) |
| `@oidfed/core` | [Statements, keys, chains, policies, endpoint clients, Trust Marks, and shared contracts](api/core/README.md) |
| `@oidfed/authority` | [Trust Anchors, Intermediates, subordinate management, and storage](api/authority/README.md) |
| `@oidfed/leaf` | [Participant publication and composed federation services](api/leaf/README.md) |
| `@oidfed/oidc` | [OIDC/OAuth roles and registration](api/oidc/README.md) |
| `@oidfed/wallet` | [Wallet roles, attestations, and federation-backed request verification](api/wallet/README.md) |
