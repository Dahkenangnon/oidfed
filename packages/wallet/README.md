# @oidfed/wallet

Wallet Provider, Credential Issuer, and Credential Verifier roles for [OpenID Federation for Wallet Architectures 1.0, Draft 05](https://openid.net/specs/openid-federation-wallet-1_0-05.html).

Compose roles into `@oidfed/leaf` or `@oidfed/authority`. Wallet applications can use their static discovery and verification methods without a federation identity. Core supplies trust-chain validation, metadata policies, key resolution, and replay storage contracts.

Install `@oidfed/wallet` for standalone wallet operations, or use `pnpm add @oidfed/leaf @oidfed/wallet` to compose a wallet role into a Leaf. Both packages install core automatically.

The package supports JWT Wallet Attestations, proof-of-possession authentication, federation-backed Request Object checks, supplied chains, offline validation, and credential-format integrations. Your VCI/VP engine owns protocol endpoints, sessions, credential selection, and presentation processing.

See the [wallet API reference](../../docs/api/wallet/README.md) for public roles, signatures, validation contracts, and usage examples.

All three roles expose `parsePublicationMetadata()` for partial publications and `parseMetadata()` for completed effective metadata. Matching `*PublicationMetadata` types are available from the package entrypoint; see the [metadata reference](../../docs/api/wallet/wallet.md#walletprovidermetadata).
