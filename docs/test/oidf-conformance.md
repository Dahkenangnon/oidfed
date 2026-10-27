# OpenID Foundation conformance checks

These checks run the Foundation's Federation test modules against disposable
applications built with oidfed. They supplement the package and HTTPS tests.
Passing them does not certify oidfed: the three pinned Federation plans are
marked `alpha = true` and `certifiable = false` in the
[Foundation suite source](https://github.com/openid-certification/conformance-suite/tree/23353b36957d6466010de767c812d2c91ed37638/src/main/java/net/openid/conformance/openid/federation).

## Run locally

Install the repository dependencies with `pnpm install --frozen-lockfile`. You
also need Docker with Compose, Git, OpenSSL, and Python 3.11 or later. The harness
builds the upstream Java 21 application in a pinned Maven container. Java and
Maven are not required on the host. The first run downloads the suite, container
images, Maven dependencies, and Python dependencies, so allow time and disk space
for those downloads.

```bash
pnpm test:conformance:unit   # driver failure and cleanup checks; no Docker
pnpm typecheck:conformance  # TypeScript fixtures
pnpm test:conformance       # deployed-entity plan against TA, IA, and leaf
pnpm test:conformance:full  # deployed checks plus joined-federation OP/RP plans
```

Use `python3 tests/conformance/run.py --profile rp` or `--profile op` to
investigate either joined-federation plan independently. Both selectors are also
available through manual workflow dispatch.

To use an existing clean suite checkout, run:

```bash
python3 tests/conformance/run.py --profile full --source /path/to/conformance-suite
```

The checkout must match the revision in
[`baseline.json`](../../tests/conformance/baseline.json). The harness rejects a
different revision or local source changes and checks the plan inventory
before building. It does not patch the Foundation's tests.

Each run creates its own Compose project, network, database, CA, TLS certificate,
Federation keys, protocol keys, and suite aliases. The suite, Trust Anchor,
Intermediate, leaf, OP, and RP communicate through HTTPS names inside that
network. No ports are published on the host. Node, Python, and Java trust the
disposable CA; TLS verification remains enabled.
The Node fixture, proxy, and Java backend allow headers up to 64 KiB so the
query-delivery tests can carry RSA-signed Trust Chains. This is a bounded test
configuration, not a recommendation for production request limits.

The launcher removes containers, volumes, the network, and private run files on
normal completion or an exception. It also handles `SIGTERM`. An uncatchable
process termination or Docker failure can leave resources behind; use the
printed Compose project name to identify and remove that run.

## What runs

The baseline pins revision
`23353b36957d6466010de767c812d2c91ed37638` of the
[official read-only GitHub mirror](https://github.com/openid-certification/conformance-suite).
The canonical upstream repository is
[openid/conformance-suite on GitLab](https://gitlab.com/openid/conformance-suite).
All profiles use discovery metadata and automatic client registration.

| Plan | Modules in the pinned plan | Fixture |
|---|---:|---|
| Deployed Federation entity | 5 | Each of TA, IA, and leaf: 15 executions |
| Entity joined to test federation, OP | 20 | oidfed Federation registration with `oidc-provider` |
| Entity joined to test federation, RP | 10 | oidfed trusted discovery and Request Objects with `openid-client` |

The deployed plan checks Entity Configuration, Fetch error cases, configured
anchor keys, and the manually built chain against the Resolve response. Its
List-and-Fetch traversal module is commented out upstream and is not counted as
coverage here.

The OP/RP fixtures support authorization-code flows, including the protocol
engine's token and ID Token checks. The OP fixture logs in and grants consent for
a disposable user. The suite's own headless browser drives OP requests. The RP
fixture uses state, nonce, PKCE, and protocol keys resolved from trusted
Federation metadata. Its login target is fixed to the suite's test issuer.
These applications are test integrations, not examples of production user login
or consent policy.

### Current OP interoperability blocker

The pinned OP plan signs Request Objects with `typ: JWT`: its
[`SignRequestObjectWithFederationTrustChain`](https://github.com/openid-certification/conformance-suite/blob/23353b36957d6466010de767c812d2c91ed37638/src/main/java/net/openid/conformance/openid/federation/SignRequestObjectWithFederationTrustChain.java)
inherits the generic type from
[`AbstractSignJWT`](https://github.com/openid-certification/conformance-suite/blob/23353b36957d6466010de767c812d2c91ed37638/src/main/java/net/openid/conformance/condition/client/AbstractSignJWT.java).
oidfed requires `oauth-authz-req+jwt` in its
[automatic-registration validator](../../packages/oidc/src/registration/validate-request-object.ts).
[RFC 9101 §10.8](https://www.rfc-editor.org/rfc/rfc9101.html#section-10.8)
describes explicit typing as a defense against JWT confusion and permits requiring
it in new deployment profiles. This is an interoperability mismatch between the
suite and oidfed's policy, rather than a finding that either side violates a
mandatory typing requirement.

The OP profile therefore fails at its first positive flow. Later OP modules are
not established as coverage by that failed run. The driver preserves the suite's
signed requests and oidfed's typing policy, and reports the failure. Resolving
this blocker requires an upstream configuration or test change
that supports explicitly typed Request Objects, followed by a new pinned baseline.

### Current RP token-response blocker

The RP's first six negative Entity Configuration and registration-type tests
pass. Its positive flow reaches token issuance, and the Foundation module reports
`PASSED`. The application still rejects the response: the pinned suite's
[`OpenIDFederationClientTest.tokenResponse()`](https://github.com/openid-certification/conformance-suite/blob/23353b36957d6466010de767c812d2c91ed37638/src/main/java/net/openid/conformance/openid/federation/client/OpenIDFederationClientTest.java#L379-L411)
returns only `id_token`, omitting `access_token` and `token_type`.
[OpenID Connect Core §3.1.3.3](https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse)
requires an Access Token in a successful code-flow response;
[OAuth 2.0 §5.1](https://www.rfc-editor.org/rfc/rfc6749.html#section-5.1)
requires both response fields. The fixture's `openid-client` engine rejects the
missing Access Token before validating the ID Token.

The driver requires application acceptance as well as the suite's result, so
this run fails. The harness does not fabricate token fields or weaken token
validation. A corrected upstream token response and a new pinned baseline are
needed to establish positive-flow and later ID Token rejection coverage. The
full profile stops at this failure, before the independently verified OP typing
blocker described above.

These tests also exposed an oidfed transport defect, fixed alongside the harness:
OIDC query, form-post, and hosted Request Object delivery now repeat the supplied
`scope` and `response_type` outside the JWT, matching the signed values under
[OpenID Connect Core §§6.1–6.2](https://openid.net/specs/openid-connect-core-1_0.html#RequestObject).
[JAR §5](https://www.rfc-editor.org/rfc/rfc9101.html#section-5)
permits these matching parameters. OAuth-only delivery and PAR retain their
existing behavior; [PAR §3](https://www.rfc-editor.org/rfc/rfc9126.html#section-3)
keeps authorization parameters inside the Request Object. Package regressions
cover these transport boundaries, and the harness uses the generated URL unchanged.

The package tests still cover behavior that these plans do not exercise. In
particular, this baseline has no dedicated plans for Extended Listing Draft 03,
Subordinate Events Draft 01, Entity Collection Draft 01, or Wallet Federation
Draft 05. A broader Foundation OIDC or wallet plan does not establish Federation
extension coverage. Trust Mark tests are tracked in an
[upstream proposal](https://gitlab.com/openid/conformance-suite/-/work_items/1880).

## Results and failures

The driver uses the upstream Python API wrapper to create plans and execute
their modules. It checks the returned inventory against the baseline, executes
modules without automatic reruns, and requires a finished lifecycle **and** a
passing result.
Warnings, manual-review results, unexpected skips, missing logs, interrupted
modules, and timeouts fail the run. The exported results must contain every
executed instance and agree with the API results. The driver does not rerun a
failed module to obtain a pass.

Two capability-dependent skips are accepted:

- The two Fetch tests on the leaf, which does not advertise a Fetch endpoint.
- The encrypted Request Object test when the OP does not advertise Request
  Object encryption algorithms and methods.

Each accepted skip remains visible as `SKIPPED` in the report. Other skipped
modules fail, including those same Fetch tests on the authority fixtures.

Reports are written under `.conformance/runs/<run-id>/results/`:

- `build.json` records the suite revision, JAR and fixture digests, oidfed commit,
  working-tree state, runner image, and profile.
- `summary.json` records each module, fixture, status, result, acceptance decision,
  and failing condition identifiers. An infrastructure error also fails the run.

Raw suite logs and exports can contain private test keys, assertions, cookies,
and authorization codes. They stay in the private run directory and are removed
during cleanup. Only the bounded report fields are uploaded to GitHub.

For local diagnosis, add `--keep-private` to the Python launcher command. It
retains sensitive diagnostics under the run's `private/` directory while still
removing Docker resources. This option is prohibited in CI. Keep these files
local, never attach them to an issue or PR, and remove them after diagnosis.

Start an investigation with the module and condition identifiers in the summary.
Distinguish a fixture integration error, a protocol-engine error, a suite defect,
and an oidfed defect. Check the current source and the applicable specification
before changing behavior. Report a confirmed library defect in a linked issue;
do not weaken validation or add an expected-failure exception to make a run pass.

## CI and baseline maintenance

The [conformance workflow](../../.github/workflows/conformance.yml) runs the
deployed profile for pull requests. On `main` and nightly, it runs deployed, RP,
and OP in separate jobs with matrix fail-fast disabled, so one plan's failure
cannot prevent another from running. Manual dispatch supports the sequential
full profile and individual plans. The workflow has a
45-minute job limit, read-only repository permissions, no deployment credentials,
and 14-day report retention.

Do not require this new check in branch protection until both profiles have
passed on at least three independent clean CI workers. Keep package and HTTPS
checks required during that period. Making conformance required is a separate
maintainer setting; this change does not update repository protection rules.

To update the suite, review its source and relevant specification changes,
update the pinned revision and module inventory together, and run both profiles
from a clean environment. Re-evaluate every allowed skip. Container digests and
Python dependencies are also pinned and need deliberate updates. Record actual
coverage changes without changing the implemented specification drafts merely
to match an upstream test assumption.

## Hosted milestone checks and certification

The Foundation provides
[hosted and local testing](https://openid.net/certification/about-conformance-suite/).
Hosted testing is useful before a release as an independent environment; it is
not needed by CI. Follow the Foundation's
[Federation testing instructions](https://openid.net/certification/federation_testing/)
and compare configuration fields with the suite revision being used.

For a hosted check, a maintainer must sign in to the Foundation service, provide
a separate publicly reachable HTTPS test deployment, and configure its plans.
Use disposable identities and keys. Do not expose the local suite's development
authentication mode publicly. For the deployed plan, configure the target Entity
Identifier, `federation.de_trust_anchor`, and its public
`federation.de_trust_anchor_jwks`. Joined OP/RP plans require enrolling the test
entity under the suite-generated Trust Anchor and trusting its keys explicitly.
Use unique aliases and keep results unpublished unless publication is intended.
The isolated `.ofed.test` fixtures are not reachable by the hosted service.

The harness creates no hosted accounts, deployments, or certification requests.
Before seeking certification, confirm that Federation certification is available
and which profiles and suite versions are accepted. Follow the Foundation's
[open-source certification policy](https://openid.net/certification/open-source-project-certification-policy/)
where applicable. Do not describe these alpha test results as certification.
