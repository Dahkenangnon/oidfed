# OpenID Federation conformance checks

The harness runs OpenID Federation test plans from the OpenID Foundation's
conformance suite against disposable oidfed applications. These checks supplement
the package and HTTPS tests.

## Run locally

Install the repository dependencies with `pnpm install --frozen-lockfile`.
You also need Docker with Compose, Git, and OpenSSL. The TypeScript harness
builds the upstream Java 21 application in a pinned Maven container, so you do
not need Java or Maven on the host. Allow time and disk space for the first run
to download the suite, container images, and Maven dependencies.

```bash
pnpm test:conformance:unit   # driver failure and cleanup checks; no Docker
pnpm typecheck:conformance  # TypeScript harness and fixtures
pnpm test:conformance       # deployed-entity plan against TA, IA, and leaf
pnpm test:conformance:full  # deployed checks plus joined-federation OP/RP plans
```

Run either joined-federation plan on its own with the TypeScript launcher:

```bash
pnpm exec tsx --tsconfig tests/conformance/tsconfig.json tests/conformance/run.ts --profile rp
pnpm exec tsx --tsconfig tests/conformance/tsconfig.json tests/conformance/run.ts --profile op
```

You can also select either plan through manual workflow dispatch.

To use an existing clean suite checkout, run:

```bash
pnpm exec tsx --tsconfig tests/conformance/tsconfig.json tests/conformance/run.ts --profile full --source /path/to/conformance-suite
```

The checkout must match the revision in
[`baseline.json`](../../tests/conformance/baseline.json) and have no local source
changes. Before building, the harness verifies the revision and plan inventory.
It runs the upstream tests without patches.

Each run creates its own Compose project, network, database, CA, TLS certificate,
Federation keys, protocol keys, and suite aliases. The suite, Trust Anchor,
Intermediate, leaf, OP, and RP communicate over HTTPS inside that network.
No ports are published on the host. Node and Java trust the disposable CA,
with TLS verification enabled.

The Node fixture, proxy, and Java backend allow headers up to 64 KiB so
query-delivery tests can carry RSA-signed Trust Chains. This limit is specific
to the tests; it is not guidance for production request limits.

The launcher removes containers, volumes, the network, and private run files
when a run completes, raises an exception, or receives `SIGTERM`. An uncatchable
process termination or Docker failure can leave resources behind. Use the
printed Compose project name to find and remove that run's resources.

## What runs

The baseline pins revision
`23353b36957d6466010de767c812d2c91ed37638` of the
[official read-only GitHub mirror](https://github.com/openid-certification/conformance-suite).
The canonical upstream repository is
[openid/conformance-suite on GitLab](https://gitlab.com/openid/conformance-suite).
All profiles use discovery metadata and automatic client registration.

| Plan (upstream short name) | Modules in the pinned plan | Fixture |
|---|---:|---|
| [Deployed federation entity](https://github.com/openid-certification/conformance-suite/blob/23353b36957d6466010de767c812d2c91ed37638/src/main/java/net/openid/conformance/openid/federation/OpenIDFederationDeployedEntityTestPlan.java) | 5 | Each of TA, IA, and leaf: 15 executions |
| [Entity joined to test federation (OP)](https://github.com/openid-certification/conformance-suite/blob/23353b36957d6466010de767c812d2c91ed37638/src/main/java/net/openid/conformance/openid/federation/OpenIDFederationClientRegistrationOPTestPlan.java) | 20 | oidfed Federation registration with `oidc-provider` |
| [Entity joined to test federation (RP)](https://github.com/openid-certification/conformance-suite/blob/23353b36957d6466010de767c812d2c91ed37638/src/main/java/net/openid/conformance/openid/federation/client/OpenIDFederationClientRegistrationRPTestPlan.java) | 10 | oidfed trusted discovery and Request Objects with `openid-client` |

The deployed plan checks Entity Configuration, Fetch error cases, and configured
anchor keys. It also compares a manually built chain with the Resolve response.
The upstream plan comments out its List-and-Fetch traversal module, so that
module provides no coverage in this baseline.

The OP and RP fixtures support authorization-code flows, including token and
ID Token checks by their protocol engines. The suite's headless browser drives
OP requests; the OP fixture logs in and grants consent for a disposable user.
The RP fixture uses state, nonce, PKCE, and protocol keys resolved from trusted
Federation metadata. It always logs in against the suite's test issuer.
The fixtures' login and consent policies are for testing only.

### Current OP interoperability blocker

The pinned OP plan signs Request Objects with `typ: JWT`: its
[`SignRequestObjectWithFederationTrustChain`](https://github.com/openid-certification/conformance-suite/blob/23353b36957d6466010de767c812d2c91ed37638/src/main/java/net/openid/conformance/openid/federation/SignRequestObjectWithFederationTrustChain.java)
inherits the generic type from
[`AbstractSignJWT`](https://github.com/openid-certification/conformance-suite/blob/23353b36957d6466010de767c812d2c91ed37638/src/main/java/net/openid/conformance/condition/client/AbstractSignJWT.java).
oidfed requires `oauth-authz-req+jwt` in its
[automatic-registration validator](../../packages/oidc/src/registration/validate-request-object.ts).
[RFC 9101 §10.8](https://www.rfc-editor.org/rfc/rfc9101.html#section-10.8)
describes explicit typing as a defense against JWT confusion and allows new
deployment profiles to require it. The suite's type header differs from oidfed's
policy. This failure does not establish that either side violates a mandatory
typing requirement.

The OP profile fails at its first positive flow, leaving later modules
unverified. The harness reports the failure and preserves both the suite's
signed requests and oidfed's typing policy. To resolve this blocker, the
upstream configuration or tests must support explicitly typed Request Objects.
The baseline can then be updated to a revision with that support.

### Current RP token-response blocker

The RP's first six negative Entity Configuration and registration-type tests
pass. Its positive flow reaches token issuance, and the suite module reports
`PASSED`. The application still rejects the response: the pinned suite's
[`OpenIDFederationClientTest.tokenResponse()`](https://github.com/openid-certification/conformance-suite/blob/23353b36957d6466010de767c812d2c91ed37638/src/main/java/net/openid/conformance/openid/federation/client/OpenIDFederationClientTest.java#L379-L411)
returns only `id_token`, omitting `access_token` and `token_type`.
[OpenID Connect Core §3.1.3.3](https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse)
requires an Access Token in a successful code-flow response;
[OAuth 2.0 §5.1](https://www.rfc-editor.org/rfc/rfc6749.html#section-5.1)
requires both response fields. The fixture's `openid-client` engine rejects
the response for its missing Access Token before validating the ID Token.

The harness requires the application to accept a positive flow, even when the
suite reports success. This run therefore fails. It preserves token validation
and does not add the missing fields. The upstream token response must be fixed
and the baseline updated before the positive flow and later ID Token rejection
tests can establish coverage. The full profile stops at this RP failure; the OP
typing failure is verified in a separate run.

The suite also exposed a transport defect in oidfed. OIDC query, form-post,
and hosted Request Object delivery now repeat the supplied
`scope` and `response_type` outside the JWT, matching the signed values under
[OpenID Connect Core §§6.1 and 6.2](https://openid.net/specs/openid-connect-core-1_0.html#RequestObject).
[JAR §5](https://www.rfc-editor.org/rfc/rfc9101.html#section-5)
permits these matching parameters. OAuth-only delivery and PAR retain their
existing behavior; [PAR §3](https://www.rfc-editor.org/rfc/rfc9126.html#section-3)
keeps authorization parameters inside the Request Object. Package regressions
cover these transport boundaries, and the harness uses the generated URL unchanged.

Keep running the package tests for behavior these plans do not exercise.
This baseline has no dedicated plans for Extended Listing Draft 03,
Subordinate Events Draft 01, Entity Collection Draft 01, or Wallet Federation
Draft 05. Broader OIDC or wallet plans in the conformance suite do not establish
Federation extension coverage. Trust Mark tests are tracked in an
[upstream proposal](https://gitlab.com/openid/conformance-suite/-/work_items/1880).

## Results and failures

The TypeScript API client creates plans and executes their modules through the
OpenID Foundation conformance suite's HTTP API. Vitest reports one named test per
module and target; the protocol assertions run in the unmodified Java suite.
The harness checks the returned inventory against the baseline. Each module
must finish with a passing result, apart from the capability skips listed below.
Modules run sequentially with retries disabled. Warnings, manual-review results,
unexpected skips, missing logs, interrupted modules, and timeouts fail the run.
Exports must contain every executed instance and agree with the API results.

Application and infrastructure errors block later cases in that profile.
Those unexecuted cases count as neither accepted skips nor coverage. Main and
nightly jobs run each plan independently.

The launcher requires a complete, passing profile report even if the test
process exits successfully. Missing or partial results fail the run. Export
checks validate ZIP integrity and agreement with API results. They reject
duplicate instances and JSON entries over 50 MB without extracting archive paths.

Two capability-dependent skips are accepted:

- The two Fetch tests on the leaf, which does not advertise a Fetch endpoint.
- The encrypted Request Object test when the OP does not advertise Request
  Object encryption algorithms and methods.

The report records accepted skips as `SKIPPED`. All other skips fail the run,
including those same Fetch tests on the authority fixtures.

Reports are written under `.conformance/runs/<run-id>/results/`:

- `build.json` records the suite revision, JAR and fixture digests, oidfed commit,
  working-tree state, runner image, and profile.
- `summary.json` records each module, fixture, status, result, acceptance decision,
  and failing condition identifiers. An infrastructure error also fails the run.

Raw suite logs and exports can contain private test keys, assertions, cookies,
and authorization codes. The harness keeps them in the private run directory
and removes them during cleanup. GitHub receives only the bounded report fields.

For local diagnosis, add `--keep-private` to the TypeScript launcher command.
This keeps sensitive diagnostics in the run's `private/` directory while
removing Docker resources. CI prohibits this option. Keep these files local,
never attach them to an issue or PR, and remove them after diagnosis.

Start with the module and condition identifiers in the summary. Check the
current source and applicable specification to determine whether the failure
comes from the fixture integration, protocol engine, suite, or oidfed. Record
confirmed library defects in a linked issue before changing behavior. Keep
validation intact and do not mark failures as expected just to make a run pass.

## CI and baseline maintenance

The [conformance workflow](../../.github/workflows/conformance.yml) runs the
deployed profile for pull requests. On `main` and nightly, it runs deployed, RP,
and OP in separate jobs with matrix fail-fast disabled, so one plan's failure
cannot prevent another from running. Manual dispatch supports the sequential
full profile and individual plans. Jobs have a 45-minute limit and read-only
repository permissions, with no deployment credentials. Reports are retained
for 14 days.

Keep this check optional in branch protection until all three profiles have
passed on at least three independent clean CI workers. Keep package and HTTPS
checks required during that period. A maintainer must enable the conformance
requirement separately; the workflow does not change repository protection rules.

To update the suite, review its source and relevant specification changes,
update the pinned revision and module inventory together, and run all three
profiles from a clean environment. Review every allowed skip again. Update
container digests and pinned harness dependencies deliberately. Record coverage
changes. Do not change oidfed's implemented specification drafts just to match
an upstream test assumption.

## Hosted milestone checks and certification

The OpenID Foundation provides
[hosted and local testing](https://openid.net/certification/about-conformance-suite/).
Hosted testing can check a deployment in an independent environment before
a release. Local CI runs do not require it. Follow the Foundation's
[Federation testing instructions](https://openid.net/certification/federation_testing/)
and compare configuration fields with the suite revision being used.

To run a hosted check, sign in to the Foundation service and configure the plans
for a separate test deployment reachable over public HTTPS. Use disposable
identities and keys, and keep the local suite's development authentication mode
off public networks. For the deployed plan, configure the target Entity
Identifier, `federation.de_trust_anchor`, and its public
`federation.de_trust_anchor_jwks`. Joined OP/RP plans require enrolling the test
entity under the suite-generated Trust Anchor and explicitly trusting its keys.
Use unique aliases. Publish results only when you intend to share them.
The hosted service cannot reach the isolated `.ofed.test` fixtures.

Account creation, public test deployment, and certification requests are
separate maintainer tasks. Before seeking certification, confirm that Federation
certification is available and which profiles and suite versions are accepted.
Follow the Foundation's
[open-source certification policy](https://openid.net/certification/open-source-project-certification-policy/)
where applicable. Do not describe these alpha test results as certification.
