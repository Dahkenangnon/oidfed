# Changelog

## [Unreleased]

## [3.0.0] - 2026-11-26

### Breaking Changes

* unify storage and federation host contracts ([2882619](https://github.com/Dahkenangnon/oidfed/commit/28826192c47f6eb898a0d1f590c87aa12b3a3d5d))
* require host-provided crypto ([d748f11](https://github.com/Dahkenangnon/oidfed/commit/d748f1168d8819ea5943433400b858e26f7030fb))
* bind verification to caller context ([c138e09](https://github.com/Dahkenangnon/oidfed/commit/c138e09808827d95c83e0b4ea3cc90c5fce47ee4))

### Features

* support shared attestation freshness and replay controls ([cead928](https://github.com/Dahkenangnon/oidfed/commit/cead928ea56a9eb3e756fa2feba3755e89aba8a6))
* integrate configurable trust establishment ([e437b4d](https://github.com/Dahkenangnon/oidfed/commit/e437b4d0cd2e03b5bd2108d2fcb49ff76b3dcfb1))
* parse concatenated attestations safely ([9701155](https://github.com/Dahkenangnon/oidfed/commit/9701155ea1bf02baa11db97131c940f7c2b50b64))
* configure attestation algorithm policies ([0ab3a77](https://github.com/Dahkenangnon/oidfed/commit/0ab3a77e58d5d0ae931e13e35ad6101ff6253c58))
* allow partial authorization server discovery ([02d8c63](https://github.com/Dahkenangnon/oidfed/commit/02d8c639f3bc3d4bbe6a239974ad7e8f0e2e0d07))
* bound supplied trust chains ([a8ed789](https://github.com/Dahkenangnon/oidfed/commit/a8ed7892a929b53b968dceca9ffdaf5434a22064))

### Bug Fixes

* correct ESM and CommonJS declaration exports ([3475f0b](https://github.com/Dahkenangnon/oidfed/commit/3475f0bbc7cc7eea7c8501e02acb83edd0970375))
* safely normalize extended DCQL queries ([b8b3681](https://github.com/Dahkenangnon/oidfed/commit/b8b3681efc67cf1aa4ad2eba1c5e1b3a6ee370cb))
* select valid request chains within shared limits ([f707670](https://github.com/Dahkenangnon/oidfed/commit/f707670dcd3fd7219a659747915bb6074d32951f))
* honor configured signing chains and trust anchors ([83ec64a](https://github.com/Dahkenangnon/oidfed/commit/83ec64a6e987120c015b280a4e5b27468f81f879))
* enforce wallet federation metadata requirements ([b0c0f2a](https://github.com/Dahkenangnon/oidfed/commit/b0c0f2a2bb73f964f3b0cfccb08fabd7aadbd9d0))
* accept valid protocol JWK sets and NumericDates ([347a3ad](https://github.com/Dahkenangnon/oidfed/commit/347a3ad450833ef1c3fe0595fda77cdac5d6d708))
* align metadata parsers with publication and discovery ([977222a](https://github.com/Dahkenangnon/oidfed/commit/977222a08658f2e58b8fe581f07ba384cc69b56f))
* report verification and offline evidence failures ([4eec989](https://github.com/Dahkenangnon/oidfed/commit/4eec9892918dfdca9e0d9a8a03e20de868f8108f))
* enforce trust-chain authority hints and offline wallet guards ([b5b3f07](https://github.com/Dahkenangnon/oidfed/commit/b5b3f074873132a460c45cf3e3b777a92cb2bbc0))
* identify invalid role metadata in errors ([b805702](https://github.com/Dahkenangnon/oidfed/commit/b805702b9dc40ddd0fba8e9dc5cefaf731d19dcf))
* reject malformed proofs before discovery ([de21129](https://github.com/Dahkenangnon/oidfed/commit/de2112901db4209a57c464e992556d37cba90cba))
* enforce confirmation key representation ([8caa999](https://github.com/Dahkenangnon/oidfed/commit/8caa999f15625cd2ec3c644381cd8948eda4a74c))
* validate confirmation keys before issuance ([3fdfa84](https://github.com/Dahkenangnon/oidfed/commit/3fdfa8441679f51512503d98c4fb048868ba0515))
* validate credential format metadata ([8eddad4](https://github.com/Dahkenangnon/oidfed/commit/8eddad4d001051a75c9aeca315a27da56ae7215a))
* validate recognized presentation query fields ([1657bad](https://github.com/Dahkenangnon/oidfed/commit/1657bad3594fd61896c56be8b4c4520dbc84382f))
* bound request freshness by explicit policy ([12a3196](https://github.com/Dahkenangnon/oidfed/commit/12a31962dbf09f35611f90b2669c9f442e00abc2))
* validate outer request parameters early ([b929f22](https://github.com/Dahkenangnon/oidfed/commit/b929f227ff926ba917c7f9a6643b2fd21757b5bd))
* consume payload trust chain hints ([65e1243](https://github.com/Dahkenangnon/oidfed/commit/65e12436db2d812a45dcd96242d3111c7050ec43))
* return errors for invalid fetch budgets ([3153825](https://github.com/Dahkenangnon/oidfed/commit/3153825260deb391c1307a4ed0b37f911df937b0))
* validate JSON claim path roots ([bed851f](https://github.com/Dahkenangnon/oidfed/commit/bed851fccce3ef213040a8d36af05f10bb086cf8))
* enforce attestation audience binding ([e14290b](https://github.com/Dahkenangnon/oidfed/commit/e14290b40d88d41394e1e8726e2a36ade7d15f7c))
* verify PoP hints against confirmation keys ([b863786](https://github.com/Dahkenangnon/oidfed/commit/b863786e99f06e136b78285bf7732c5bee0ed226))
* tighten publication and trust checks ([66e88e2](https://github.com/Dahkenangnon/oidfed/commit/66e88e2d6e53880da0d757e4a4a8932b0dfcf27f))
* validate federation boundaries ([5207ec5](https://github.com/Dahkenangnon/oidfed/commit/5207ec5a797d3b58df14b2f147b59bef69f478c2))
* accept optional protocol key identifiers ([a6dc86a](https://github.com/Dahkenangnon/oidfed/commit/a6dc86ac677175063e838e7e0be1ff28683fd9a0))
* require holder binding for transaction requests ([38bdcb5](https://github.com/Dahkenangnon/oidfed/commit/38bdcb59c00ac86955993ee45afd93c69d0d71ff))
* sanitize overridden request query lists ([ba37bc3](https://github.com/Dahkenangnon/oidfed/commit/ba37bc3493b1e5a9ba10e0ef27d1e66c3cca76d8))
* require keys for provider attestations ([2b134e5](https://github.com/Dahkenangnon/oidfed/commit/2b134e50a0b0444cc0e17108f90550f9e99a0b80))
* validate endpoint URL components ([244c72f](https://github.com/Dahkenangnon/oidfed/commit/244c72f973d71a404d2ff60862935b74568f8d5b))
* validate request response parameters ([2fd9dcc](https://github.com/Dahkenangnon/oidfed/commit/2fd9dccbd3b3a109efae08ded3e1d835e1200ec6))
* separate protocol key identifier requirements ([34ba00e](https://github.com/Dahkenangnon/oidfed/commit/34ba00ec50007360ff7c599916909dcfb433e817))

### Refactor

* share protocol helpers and remove dead code ([f299374](https://github.com/Dahkenangnon/oidfed/commit/f299374faab2822cd06c543832e0d959e5210c39))


## [2.0.0] - 2026-10-26

### Added

- Wallet Architectures Draft 05 provider, issuer, and verifier roles, composed on authority or leaf hosts. Validate role metadata and discover participants through existing core trust-chain validation. ([5863459](https://github.com/Dahkenangnon/oidfed/commit/58634591566fc500f3872b46b480d34d01a29a7b))
- JWT Wallet Attestation creation and verification, plus PoP authentication with a required replay store and application acceptance callback.
- Federation-backed presentation request preparation and completion, with endpoint checks, nonce checks, active DCQL or scope-query validation, transaction binding, and superior metadata overrides.
- Credential and alternative-attestation verification callbacks. Applications provide their VCI/VP protocol engines, credential-format processing, session binding, and framework policy.
- Offline verification using supplied chains and keys, with documented evidence lifetime and callback requirements.
