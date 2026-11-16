# Feature guides

> A federation can be expressed as an agreement between parties that trust each other.
>
> [OpenID Federation, Abstract](https://openid.net/specs/openid-federation-1_0.html#abstract)

In OpenID Federation, participants establish trust through signed statements that lead to a configured **Trust Anchor**. After validating that path, an application derives the participant's metadata under the federation's policies. The application then uses that metadata for its protocol interaction.

The academic example in [Appendix A](https://openid.net/specs/openid-federation-1_0.html#appendix-A) follows a researcher signing in through Umeå University's OP to access the LIGO Wiki:

```text
                       eduGAIN
                    [Trust Anchor]
                          |
              +-----------+-----------+
              |                       |
           SWAMID                  InCommon
        [Intermediate]          [Intermediate]
              |                       |
           umu.se                     |
        [Intermediate]                |
              |                       |
          op.umu.se              wiki.ligo.org
          [Leaf: OP]              [Leaf: RP]
```

The branches show federation relationships, not browser redirects. Both participants can establish paths to eduGAIN even though their immediate Superiors differ. SWAMID and InCommon can also act as Trust Anchors for their own federations; the diagram shows their intermediate position under eduGAIN.

These guides connect that model to `TrustAnchor`, `Intermediate`, and `Leaf`, and to the OIDC and Wallet role APIs. The [Wallet overview](16.wallet.md) uses a separate driving licence example based on the Wallet specification's architecture. Runnable examples use the reserved addresses listed below.

## Choose a topic

| Guide | What you can do |
|---|---|
| [1. Federation participants](1.federation-participants.md) | Choose hosts, configure anchors, and enroll participants. |
| [2. Entity Statements](2.entity-statements.md) | Publish Entity Configurations and issue Subordinate Statements. |
| [3. Trust chains](3.trust-chains.md) | Validate chains, supply offline evidence, and use chain headers. |
| [4. Metadata](4.metadata.md) | Publish, complete, and validate metadata; resolve protocol keys. |
| [5. Federation policy](5.federation-policy.md) | Apply metadata policies and constraints, including custom extensions. |
| [6. Trust Marks](6.trust-marks.md) | Issue, delegate, publish, and verify accreditation. |
| [7. Federation endpoints](7.federation-endpoints.md) | Serve and call federation endpoints with the required authentication. |
| [8. Discovery and caching](8.discovery.md) | Discover participants, select paths, and manage caches. |
| [9. Updates, rollover, and revocation](9.updates-and-keys.md) | Update participants, rotate keys, and refresh trust decisions. |
| [10. Localized information](10.localized-information.md) | Publish and select information in different languages. |
| [11. Operating a federation application](11.operations.md) | Connect HTTP handlers, durable storage, replay protection, and logging. |

### Federation extensions

| Guide | What you can do |
|---|---|
| [12. Extended Subordinate Listing](12.extended-listing.md) | Filter and paginate subordinate listings with selected claims. |
| [13. Subordinate Events](13.subordinate-events.md) | Record and retrieve subordinate lifecycle history. |
| [14. Entity Collection](14.entity-collection.md) | Build and query searchable collections of participants. |

### Protocol workflows

| Guide | What you can do |
|---|---|
| [15. OIDC and OAuth workflows](15.oidc-and-oauth.md) | Connect OIDC/OAuth roles and client registration to federation trust. |
| [16. Wallet workflows](16.wallet.md) | Establish trust for wallet providers, issuers, and verifiers. |

## Shared scenarios

The topic overviews keep the relevant actors in an expandable context section. The academic story follows Federation Appendix A. The driving licence story illustrates the Wallet profile without changing its trust or protocol responsibilities.

<details>
<summary>Meet the academic federation from Appendix A</summary>

**eduGAIN** is the selected **Trust Anchor**. **SWAMID** and **InCommon** are its Intermediates in this example. SWAMID enrolls **Umeå University**, which enrolls its OP; InCommon enrolls the **LIGO Wiki**, which acts as the RP. **Maya** is the researcher signing in at her university to use the wiki.

This follows the illustrative topology in [Federation Appendix A](https://openid.net/specs/openid-federation-1_0.html#appendix-A). The runnable examples use reserved `.example` addresses, not production services. The additional **Research Portal** and **Research API** are supplementary examples for roles beyond that topology. [Example identifiers](README.md#example-entity-identifiers) keep those actors distinct.

</details>

<details>
<summary>Meet the driving licence participants</summary>

The example **Driving Licence Federation** operates a **Trust Anchor**. The **Licensing Authority** issues **Maya**'s driving licence. The **Wallet Provider** supplies her wallet solution and attests her wallet instance. The **Car Rental Company** requests a presentation and verifies it before making a rental decision.

An **Accreditation Authority** owns an example approved-verifier Trust Mark type. A **Verifier Auditor** can issue that mark under its delegation and the anchor's policy. The rental company holds the mark. These organizational roles are separate from Maya and her wallet instance.

This is an illustrative application of [Wallet Draft 05's model](https://openid.net/specs/openid-federation-wallet-1_0-05.html#section-4). The names, accreditation policy, and `.example` addresses describe this documentation's example, not a prescribed licence scheme. [Example identifiers](README.md#example-entity-identifiers) are listed in the index.

</details>

## Example Entity Identifiers

The labels in the academic diagram come from the specification's example. These executable addresses are reserved substitutes; no example calls the real organizations' services.

| Participant | Example identifier | Role |
|---|---|---|
| **eduGAIN** | `https://edugain.example` | Selected academic Trust Anchor |
| **SWAMID** | `https://swamid.example` | Intermediate under eduGAIN |
| **Umeå University** | `https://umu.example` | Intermediate under SWAMID |
| **Umeå University OP** | `https://op.umu.example` | OP Leaf under the university |
| **InCommon** | `https://incommon.example` | Intermediate under eduGAIN |
| **LIGO Wiki** | `https://wiki.ligo.example` | RP Leaf under InCommon |
| **Research Portal** | `https://portal.example` | Supplementary RP example under InCommon |
| **Research API** | `https://research-api.example` | Supplementary OAuth resource example |
| **Driving Licence Federation** | `https://licence-federation.example` | Example Wallet federation Trust Anchor |
| **Licensing Authority** | `https://licensing-authority.example` | Credential Issuer |
| **Licence Authorization Service** | `https://auth.licensing-authority.example` | Authorization server, when separate |
| **Wallet Provider** | `https://wallet-provider.example` | Wallet Provider organization |
| **Car Rental Company** | `https://car-rental.example` | Credential Verifier and accreditation holder |
| **Accreditation Authority** | `https://accreditation.example` | Example Trust Mark Owner |
| **Verifier Auditor** | `https://auditor.example` | Delegated Trust Mark Issuer |

**Maya** is the example end user. Her wallet instance has its own key and Wallet Attestation; it is distinct from the Wallet Provider's federation entity. Replace or locally route the reserved URLs when running a network example. Extra `.example` addresses in isolated snippets illustrate alternative configurations and do not change these two topologies.

## Using the examples

Start with the public host and role APIs: `TrustAnchor` and `Intermediate` from `@oidfed/authority`, `Leaf` from `@oidfed/leaf`, and the protocol roles from `@oidfed/oidc` and `@oidfed/wallet`. The guides show where to configure dependencies and which operation exercises them.

Core supplies shared contracts, key providers, and adapters. Direct core operations are used where the task needs a remote endpoint client, standalone publication, or another capability without a matching host or role operation. Those cases are explained beside their examples.

Current TypeScript blocks import public package entry points. Parameters such as `keys`, `anchors`, `signer`, and `storage` are dependencies supplied by the host. Memory adapters and generated keys demonstrate one-process behavior; deployments supply durable state and suitable key custody.

Inspect `result.ok` before reading `result.value`. Chain validation uses `valid`; metadata parsers use `success`.

Inline code identifies API names, claim names, literal values, and normative keywords such as `MUST` or `SHOULD`. **Bold** highlights example participants and important concepts. Specification references remain next to the behavior they support; code formatting alone does not indicate a verbatim quotation.

The [API reference](../api/README.md) lists public APIs and their contracts. For repository changes, follow [Contributing](../../CONTRIBUTING.md).

[Next: 1. Federation participants](1.federation-participants.md)
