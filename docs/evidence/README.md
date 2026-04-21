# OpenID Federation 1.0 — Compliance Evidence

**Spec:** [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html) (Final, 17 February 2026)
**Date:** 2026-04-15

> **Note:** Requirement text is extracted from the specification but may be trimmed for brevity. Trimmed portions are indicated with `...`. Always refer to the [canonical specification](https://openid.net/specs/openid-federation-1_0.html) for authoritative normative language.

---

## Evidence Files by RFC 2119 Compliance Level

Each file covers one compliance level as defined by [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119) / [RFC 8174](https://datatracker.ietf.org/doc/html/rfc8174). Equivalent keywords are grouped per the RFC definitions.

| File | RFC 2119 Keywords | Level |
|------|-------------------|-------|
| [MUST.md](MUST.md) | MUST, REQUIRED, SHALL | Absolute requirement |
| [MUST-NOT.md](MUST-NOT.md) | MUST NOT, SHALL NOT | Absolute prohibition |
| [SHOULD.md](SHOULD.md) | SHOULD, RECOMMENDED | Recommended unless good reason to deviate |
| [SHOULD-NOT.md](SHOULD-NOT.md) | SHOULD NOT, NOT RECOMMENDED | Discouraged unless good reason to include |
| [MAY.md](MAY.md) | MAY, OPTIONAL | Truly optional |
| [operator-responsibilities.md](operator-responsibilities.md) | *(non-normative)* | Deployment/infrastructure concerns |

---

## Status Legend

| Status | Meaning |
|--------|---------|
| `Implemented` | Normative requirement fully implemented and tested |
| `Partial` | Partially implemented; see Notice column |
| `Not Implemented` | Not yet implemented |
| `N/A` | Not applicable to this library (infra/deployment concern, or language-inherent) |

---

## Cross-Reference by Spec Section

Cells show `implemented/total` requirement count per level. A dash (`—`) means no requirements exist at that level for the section. Informative sections (examples, references) are marked accordingly.

<!-- Counts to be populated during content migration from EVIDENCES.md -->

| Section | Title | MUST | MUST NOT | SHOULD | SHOULD NOT | MAY |
|---------|-------|------|----------|--------|------------|-----|
| §1 | Introduction | | | | | |
| §1.1 | Requirements Notation and Conventions | — | — | — | — | — |
| §1.2 | Terminology | | | | | |
| §2 | Overall Architecture | — | — | — | — | — |
| §2.1 | Cryptographic Trust Mechanism | — | — | — | — | — |
| §3 | Entity Statement | | | | | |
| §3.1 | Entity Statement Claims | | | | | |
| §3.1.1 | Claims in both ECs and SSs | | | | | |
| §3.1.2 | Claims in ECs only | | | | | |
| §3.1.3 | Claims in SSs only | | | | | |
| §3.1.4 | Claims in Explicit Registration Requests | | | | | |
| §3.1.5 | Claims in Explicit Registration Responses | | | | | |
| §3.2 | Entity Statement Validation | | | | | |
| §3.3 | Entity Statement Example | *(informative)* | | | | |
| §4 | Trust Chain | | | | | |
| §4.1 | Beginning and Ending Trust Chains | | | | | |
| §4.2 | Trust Chain Example | *(informative)* | | | | |
| §4.3 | Trust Chain Header Parameter | | | | | |
| §4.4 | Peer Trust Chain Header Parameter | | | | | |
| §5 | Metadata | | | | | |
| §5.1 | Entity Type Identifiers | | | | | |
| §5.1.1 | Federation Entity | | | | | |
| §5.1.2 | OpenID Connect Relying Party | | | | | |
| §5.1.3 | OpenID Connect OpenID Provider | | | | | |
| §5.1.4 | OAuth Authorization Server | | | | | |
| §5.1.5 | OAuth Client | | | | | |
| §5.1.6 | OAuth Protected Resource | | | | | |
| §5.2 | Common Metadata Parameters | | | | | |
| §5.2.1 | Parameters for JWK Sets in Entity Metadata | | | | | |
| §5.2.1.1 | Usage of jwks, jwks_uri, and signed_jwks_uri | | | | | |
| §5.2.2 | Informational Metadata Parameters | | | | | |
| §6 | Federation Policy | | | | | |
| §6.1 | Metadata Policy | | | | | |
| §6.1.1 | Principles | | | | | |
| §6.1.2 | Structure | | | | | |
| §6.1.3 | Operators | | | | | |
| §6.1.3.1 | Standard Operators | | | | | |
| §6.1.3.1.1 | `value` | | | | | |
| §6.1.3.1.2 | `add` | | | | | |
| §6.1.3.1.3 | `default` | | | | | |
| §6.1.3.1.4 | `one_of` | | | | | |
| §6.1.3.1.5 | `subset_of` | | | | | |
| §6.1.3.1.6 | `superset_of` | | | | | |
| §6.1.3.1.7 | `essential` | | | | | |
| §6.1.3.1.8 | Notes on Operators | | | | | |
| §6.1.3.2 | Additional Operators | | | | | |
| §6.1.4 | Enforcement | | | | | |
| §6.1.4.1 | Resolution | | | | | |
| §6.1.4.2 | Application | | | | | |
| §6.1.5 | Metadata Policy Example | *(informative)* | | | | |
| §6.2 | Constraints | | | | | |
| §6.2.1 | Max Path Length Constraint | | | | | |
| §6.2.2 | Naming Constraints | | | | | |
| §6.2.3 | Entity Type Constraints | | | | | |
| §7 | Trust Marks | | | | | |
| §7.1 | Trust Mark Claims | | | | | |
| §7.2 | Trust Mark Delegation | | | | | |
| §7.2.1 | Trust Mark Delegation JWT | | | | | |
| §7.2.2 | Validating a Trust Mark Delegation | | | | | |
| §7.3 | Validating a Trust Mark | | | | | |
| §7.4 | Trust Mark Examples | *(informative)* | | | | |
| §7.5 | Trust Mark Delegation Example | *(informative)* | | | | |
| §8 | Federation Endpoints | | | | | |
| §8.1 | Fetching a Subordinate Statement | | | | | |
| §8.1.1 | Fetch Subordinate Statement Request | | | | | |
| §8.1.2 | Fetch Subordinate Statement Response | | | | | |
| §8.2 | Subordinate Listing | | | | | |
| §8.2.1 | Subordinate Listing Request | | | | | |
| §8.2.2 | Subordinate Listing Response | | | | | |
| §8.3 | Resolve Entity | | | | | |
| §8.3.1 | Resolve Request | | | | | |
| §8.3.2 | Resolve Response | | | | | |
| §8.3.3 | Trust Considerations | | | | | |
| §8.4 | Trust Mark Status | | | | | |
| §8.4.1 | Trust Mark Status Request | | | | | |
| §8.4.2 | Trust Mark Status Response | | | | | |
| §8.5 | Trust Marked Entities Listing | | | | | |
| §8.5.1 | Trust Marked Entities Listing Request | | | | | |
| §8.5.2 | Trust Marked Entities Listing Response | | | | | |
| §8.6 | Trust Mark Endpoint | | | | | |
| §8.6.1 | Trust Mark Request | | | | | |
| §8.6.2 | Trust Mark Response | | | | | |
| §8.7 | Federation Historical Keys Endpoint | | | | | |
| §8.7.1 | Federation Historical Keys Request | | | | | |
| §8.7.2 | Federation Historical Keys Response | | | | | |
| §8.7.3 | Federation Historical Keys Revocation Reasons | | | | | |
| §8.7.4 | Rationale for Historical Keys Endpoint | *(informative)* | | | | |
| §8.8 | Client Authentication at Federation Endpoints | | | | | |
| §8.8.1 | Client Authentication Metadata | | | | | |
| §8.9 | Error Responses | | | | | |
| §9 | Obtaining Federation Entity Configuration | | | | | |
| §9.1 | Federation Entity Configuration Request | | | | | |
| §9.2 | Federation Entity Configuration Response | | | | | |
| §10 | Resolving Trust Chain and Metadata | | | | | |
| §10.1 | Fetching Entity Statements | | | | | |
| §10.2 | Validating a Trust Chain | | | | | |
| §10.3 | Choosing a Valid Trust Chain | | | | | |
| §10.4 | Calculating Trust Chain Expiration | | | | | |
| §10.5 | Transient Trust Chain Validation Errors | | | | | |
| §10.6 | Resolving with a Resolver | | | | | |
| §11 | Updating Metadata, Key Rollover, and Revocation | | | | | |
| §11.1 | Federation Key Rollover | | | | | |
| §11.2 | Key Rollover for a Trust Anchor | | | | | |
| §11.3 | Redundant Retrieval of Trust Anchor Keys | | | | | |
| §11.4 | Revocation | | | | | |
| §12 | OpenID Connect Client Registration | | | | | |
| §12.1 | Automatic Registration | | | | | |
| §12.1.1 | Authentication Request | | | | | |
| §12.1.1.1 | Using a Request Object | | | | | |
| §12.1.1.1.1 | Authorization Request with a Trust Chain | | | | | |
| §12.1.1.1.2 | Processing the Authentication Request | | | | | |
| §12.1.1.2 | Using Pushed Authorization | | | | | |
| §12.1.1.2.1 | Processing the Pushed Authentication Request | | | | | |
| §12.1.2 | Successful Authentication Response | | | | | |
| §12.1.3 | Authentication Error Response | | | | | |
| §12.1.4 | Automatic Registration and Client Authentication | | | | | |
| §12.1.5 | Possible Other Uses of Automatic Registration | *(informative)* | | | | |
| §12.2 | Explicit Registration | | | | | |
| §12.2.1 | Explicit Client Registration Request | | | | | |
| §12.2.2 | Processing Explicit Registration by OP | | | | | |
| §12.2.3 | Successful Explicit Registration Response | | | | | |
| §12.2.4 | Explicit Registration Error Response | | | | | |
| §12.2.5 | Processing Explicit Registration Response by RP | | | | | |
| §12.2.6 | Explicit Client Registration Lifetime | | | | | |
| §12.3 | Registration Validity and Trust Reevaluation | | | | | |
| §12.4 | Differences: Automatic vs Explicit Registration | *(informative)* | | | | |
| §12.5 | Rationale for Trust Chains in the Request | *(informative)* | | | | |
| §13 | General-Purpose JWT Claims | | | | | |
| §13.1 | `jwks` (JSON Web Key Set) Claim | | | | | |
| §13.2 | `metadata` Claim | | | | | |
| §13.3 | `constraints` Claim | | | | | |
| §13.4 | `crit` (Critical) Claim | | | | | |
| §13.5 | `ref` (Reference) Claim | | | | | |
| §13.6 | `delegation` Claim | | | | | |
| §13.7 | `logo_uri` (Logo URI) Claim | | | | | |
| §14 | Claims Languages and Scripts | | | | | |
| §15 | Media Types | | | | | |
| §15.1 | `application/entity-statement+jwt` | | | | | |
| §15.2 | `application/trust-mark+jwt` | | | | | |
| §15.3 | `application/resolve-response+jwt` | | | | | |
| §15.4 | `application/trust-chain+json` | | | | | |
| §15.5 | `application/trust-mark-delegation+jwt` | | | | | |
| §15.6 | `application/jwk-set+jwt` | | | | | |
| §15.7 | `application/trust-mark-status-response+jwt` | | | | | |
| §15.8 | `application/explicit-registration-response+jwt` | | | | | |
| §16 | String Operations | | | | | |
| §17 | Implementation Considerations | | | | | |
| §17.1 | Federation Topologies | | | | | |
| §17.2 | Federation Discovery and Trust Chain Resolution | | | | | |
| §17.2.1 | Bottom-Up Trust Chain Resolution | | | | | |
| §17.2.2 | Top-Down Discovery | | | | | |
| §17.2.3 | Single Point of Trust Resolution | | | | | |
| §17.3 | Trust Anchors and Resolvers Go Together | | | | | |
| §17.4 | One Entity, One Service | | | | | |
| §17.5 | Trust Mark Policies | | | | | |
| §17.6 | Related Specifications | *(informative)* | | | | |
| §18 | Security Considerations | | | | | |
| §18.1 | Denial-of-Service Attack Prevention | | | | | |
| §18.2 | Unsigned Error Messages | | | | | |
| §19 | Privacy Considerations | | | | | |
| §19.1 | Entity Statement Privacy | | | | | |
| §19.2 | Trust Mark Status Privacy | | | | | |
| §19.3 | Fetch Endpoint Privacy | | | | | |
| §20 | IANA Considerations | | | | | |
| §20.1 | OAuth Dynamic Client Registration Metadata | | | | | |
| §20.2 | OAuth Authorization Server Metadata | | | | | |
| §20.3 | OAuth Protected Resource Metadata | | | | | |
| §20.4 | OAuth Parameters Registration | | | | | |
| §20.5 | OAuth Extensions Error Registration | | | | | |
| §20.6 | JWS and JWE Header Parameters | | | | | |
| §20.7 | JSON Web Key Parameters | | | | | |
| §20.8 | JSON Web Token Claims | | | | | |
| §20.9 | Well-Known URI Registration | | | | | |
| §20.10 | Media Type Registration | | | | | |
| §21 | References | — | — | — | — | — |
| §21.1 | Normative References | — | — | — | — | — |
| §21.2 | Informative References | — | — | — | — | — |
