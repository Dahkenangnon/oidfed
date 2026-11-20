# @oidfed/crypto

Portable cryptographic operations, signing custody, keyring snapshots, and compact JSON JWS helpers. Applications can use Web Crypto, the optional JOSE adapter, or their own implementation.

```sh
pnpm add @oidfed/crypto
```

| Import | Responsibility | Runtime dependency |
| --- | --- | --- |
| `@oidfed/crypto` | Contracts, codecs, JWK utilities, compact signing/parsing, keyrings | None |
| `@oidfed/crypto/web` | Web Crypto engine and JWK-backed `SoftwareSigner` | Host Web Crypto, resolved when constructed |
| `@oidfed/crypto/jose` | JOSE verification engine | Optional `jose` v6 peer and host Web Crypto |

The root and `/web` imports do not install or import JOSE. ESM and CommonJS exports include matching declarations. Public declarations work with ES2022 types without requiring DOM or Node declaration packages. Importing the package does not initialize a crypto backend.

The root helpers use ES2022 JavaScript and typed arrays. UTF-8 handling and JWK copies work without `TextEncoder`, `TextDecoder`, `structuredClone`, `Buffer`, `atob` or `btoa`. A host can supply its engine and signing bindings without installing global crypto or encoding polyfills.

Core and the federation hosts use these contracts through explicit application configuration. See the [migration guide](../../docs/api/migration-v3.md#host-provided-crypto) for awaited host factories, managed role publication and standalone verification.

## Sign with host-owned custody

```ts
import { StaticKeyring, signCompactJws, toPublicJwk, type Signer } from "@oidfed/crypto";
import { createWebCryptoEngine } from "@oidfed/crypto/web";

const pair = await crypto.subtle.generateKey(
  { name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"],
);
const publicJwk = {
  ...toPublicJwk({ ...await crypto.subtle.exportKey("jwk", pair.publicKey), kty: "EC" }),
  kid: "signing-2026-01", alg: "ES256" as const,
};
const signer: Signer = {
  publicJwk,
  async sign(input) {
    return new Uint8Array(await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" }, pair.privateKey, new Uint8Array(input),
    ));
  },
};
const keyring = new StaticKeyring({ signers: { application: signer } });
const snapshot = await keyring.entry("application");
const compact = await signCompactJws(
  { jwks: snapshot.publishedJwks, message: "hello" },
  { alg: snapshot.signer.publicJwk.alg, kid: snapshot.signer.publicJwk.kid },
  snapshot.signer,
);
const engine = createWebCryptoEngine();
```

The private key in this example is non-exportable. A keystore, hardware device, or remote service can implement the same `Signer` contract. Bind the operation to an immutable key identifier and algorithm; do not resolve a mutable "current key" alias inside `sign`. Signers return raw JWS signature bytes, including fixed-width `R || S` for ECDSA. `SoftwareSigner` is available from `/web` for private JWKs with explicit `kid` and `alg`. The signer shares an in-flight import across calls, releases its private JWK copy after a successful import and retries a failed import on the next call.

Read the signing binding and advertised keys from one `KeyringEntry`, as above. Keep that snapshot through payload construction and signing. A snapshot remains bound to its original key when the keyring rotates. Hosts control request cancellation and backend revocation if already-issued snapshots must stop signing.

## Verification boundary

`decodeCompactJws()` reads encoded JSON header and payload objects for inspection. It leaves algorithm values, critical headers and the signature segment uninterpreted. `parseCompactJws()` additionally checks supported headers and signature encoding. Both return **unverified** data.

`CryptoEngine.verify()` consumes the original `signingInput` and `signature` bytes with the caller-selected algorithm and public key. These bytes are authoritative; the JOSE adapter reconstructs its serialization from them without reserializing JSON. Use the algorithm from the parsed protected header and require the verification result to be literally `true`. The parsed `compact` string is retained for inspection, not passed as a second verification representation.

Protocol code must separately apply algorithm policy, select trusted keys, enforce its `typ` and `kid` rules, validate claims and audience, and establish trust. There is deliberately no generic JWT verification helper in this package. A valid signature alone does not establish federation trust. [OpenID Federation §3](https://openid.net/specs/openid-federation-1_0-final.html#section-3) recommends RS256 verification and requires explicit `typ` and `kid` for Entity Statements; those rules belong in the protocol verifier.

Both adapters enable ES256/384/512, PS256/384/512 and RS256 by default. Ed25519 and its legacy `EdDSA` identifier require explicit opt-in and runtime support. `algorithms` advertises the adapter's configured capability ceiling, not deployment acceptance policy or a runtime probe. Deployments should narrow accepted algorithms per operation. `INTEROP_RECOMMENDED_ALGORITHMS` contains RS256 as guidance and does not change policy.

## Key rotation

`MemoryRotatingKeyring` supports arbitrary purpose names and an empty initial map:

1. `publish(purpose, nextSigner)` includes the next public key before it signs.
2. Allow the application's propagation interval to elapse.
3. `activate(purpose, nextKid)` selects the new signer and keeps the old public key during overlap.
4. `retire(purpose, oldKid)` withdraws the old public key after outstanding tokens expire.
5. `revoke(purpose, kid, reason)` withdraws a compromised key immediately from future snapshots.

`history(purpose)` records publication, activation, retirement and revocation events in Unix seconds; active keys have no invented end time. `publishedAt` records introduction into this keyring. It does not establish when the key was created or when a remote party received its JWKS. Pending keys enter history only after activation or withdrawal. Historical records are building blocks for a host's historical-key endpoint; protocol code maps their meaning to wire fields. The injectable clock must be finite and nondecreasing. A rejected clock read leaves state unchanged. This keyring is in-memory; durable, distributed rotation and propagation schedules belong to the application.

`StaticKeyring` offers explicit one-hop purpose aliases and additional published keys. Neither implementation implicitly shares a federation signer with another purpose. Custom keyrings can use `KeySelectionContext` for issuer, subject, trust-mark type and application extension facts.

## Application algorithms

Use `createJwsAlgorithmRegistry` to add an algorithm and its public key format. Share the registry across your host, keyring and standalone operations. Select the permitted Federation Entity Key algorithms with `allowedFederationAlgorithms`. Protocol roles apply their own algorithm settings. See the [complete custom crypto example](../../docs/examples/custom-crypto.ts).

## Adapters and support

```sh
pnpm add jose
```

```ts
import { createJoseEngine } from "@oidfed/crypto/jose";
const engine = createJoseEngine();
```

The JOSE adapter uses JOSE's global Web Crypto for verification. An explicitly injected implementation supplies its digest/random operations; it does not replace JOSE's verification backend. Use `/web` or a custom `CryptoEngine` when the whole backend must be injected.

The repository tests the package in its Node, Bun, Deno, workerd, Electron and Chromium matrix. React Native and individual native keystores are integration targets, not validated runtimes. See the [API reference](../../docs/api/crypto/README.md) and [adapter recipes](../../docs/api/crypto/adapters.md).
