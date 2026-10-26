# Changelog

## [Unreleased]

## [2.0.0] - 2026-10-26

### Added

- Wallet Architectures Draft 05 provider, issuer, and verifier roles, composed on authority or leaf hosts. Validate role metadata and discover participants through existing core trust-chain validation. ([5863459](https://github.com/Dahkenangnon/oidfed/commit/58634591566fc500f3872b46b480d34d01a29a7b))
- JWT Wallet Attestation creation and verification, plus PoP authentication with a required replay store and application acceptance callback.
- Federation-backed presentation request preparation and completion, with endpoint checks, nonce checks, active DCQL or scope-query validation, transaction binding, and superior metadata overrides.
- Credential and alternative-attestation verification callbacks. Applications provide their VCI/VP protocol engines, credential-format processing, session binding, and framework policy.
- Offline verification using supplied chains and keys, with documented evidence lifetime and callback requirements.
