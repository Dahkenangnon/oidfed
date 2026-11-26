# @oidfed/crypto

Use `@oidfed/crypto` to sign and verify compact JWS and manage the keys those operations use. Choose Web Crypto, the optional JOSE adapter, or your own implementation. Your application controls where private keys are kept and how signing runs.

```sh
pnpm add @oidfed/crypto
```

| Import | Responsibility | Runtime dependency |
| --- | --- | --- |
| `@oidfed/crypto` | Contracts, codecs, JWK utilities, compact signing/parsing, keyrings | None |
| `@oidfed/crypto/web` | Web Crypto engine and JWK-backed `SoftwareSigner` | Host Web Crypto, resolved when constructed |
| `@oidfed/crypto/jose` | JOSE verification engine | Optional `jose` v6 peer and host Web Crypto |

JOSE is optional and only the `/jose` entry point loads it. You choose a crypto backend when you configure your application. The package ships matching TypeScript declarations for ESM and CommonJS, and ES2022 types are enough to use them.

The root helpers use ES2022 JavaScript and typed arrays. They handle UTF-8 and copy JWKs without relying on `TextEncoder`, `TextDecoder`, `structuredClone`, `Buffer`, `atob` or `btoa`. You can pass in your own engine and signing bindings without installing global crypto or encoding polyfills.

Standalone Core operations take an engine in their options. Federation hosts take the engine and signing bindings in their configuration.

## Sign with host-owned custody

```ts
import { StaticKeyring, signCompactJws, toPublicJwk, type Signer } from "@oidfed/crypto";

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
```

The example keeps the private key non-exportable. You can use the same `Signer` contract with a keystore, hardware device, or remote signing service. Bind `sign` to a fixed key identifier and algorithm so it uses the same key even if the service’s “current key” changes. Return raw JWS signature bytes, using fixed-width `R || S` for ECDSA.

Use `SoftwareSigner` from `/web` if you have a private JWK with an explicit `kid` and `alg`. Concurrent calls share the same key import. The signer releases its private JWK copy once the import succeeds and tries again on the next call if the import fails.

Take the signer and the advertised keys from the same `KeyringEntry`. Use that snapshot to build and sign the payload so both operations use the same key even during rotation. If you need to stop an existing snapshot from signing, your application controls request cancellation and key revocation in the backend.

## Verification boundary

`decodeCompactJws()` reads the JSON header and payload so you can inspect them. It leaves interpretation of the algorithm, critical headers, and signature segment to the caller. `parseCompactJws()` also checks header support and signature encoding. Treat the output of either function as unverified.

Pass the original `signingInput` and `signature` bytes to `CryptoEngine.verify()` along with the selected public key and the algorithm from the parsed protected header. The JOSE adapter rebuilds the compact form from those bytes without reserializing the JSON. Accept the signature only if verification returns exactly `true`. Use the parsed `compact` string for inspection.

Use your protocol verifier to establish trust. It applies the algorithm policy, selects trusted keys, checks `typ` and `kid`, and validates the claims and audience. For Entity Statements, [OpenID Federation §3](https://openid.net/specs/openid-federation-1_0-final.html#section-3) recommends RS256 verification and requires explicit `typ` and `kid`.

Both adapters enable ES256/384/512, PS256/384/512, and RS256 by default. To use `RS384`, `RS512`, `Ed25519`, or the legacy `EdDSA` identifier, enable it explicitly and check that your runtime supports it. The `algorithms` property reports the configured capabilities. Set the accepted algorithms separately for each operation. `INTEROP_RECOMMENDED_ALGORITHMS` lists RS256 as guidance for that choice.

## Key rotation

`MemoryRotatingKeyring` accepts your own purpose names and can start with an empty map. Rotate keys in this order.

1. `publish(purpose, nextSigner)` includes the next public key before it signs.
2. Allow the application's propagation interval to elapse.
3. `activate(purpose, nextKid)` selects the new signer and keeps the old public key during overlap.
4. `retire(purpose, oldKid)` withdraws the old public key after outstanding tokens expire.
5. `revoke(purpose, kid, reason)` withdraws a compromised key immediately from future snapshots.

`history(purpose)` returns one record per key with the available publication, activation, retirement, and revocation timestamps in Unix seconds. Active keys have no end timestamp. `publishedAt` is the time this keyring recorded the key. A pending key appears in the history after activation or withdrawal. When serving a historical-key endpoint, map these records to the fields your protocol expects.

If you supply a clock, it must return finite values in nondecreasing order. The keyring keeps its state when it rejects a clock reading. The keyring stores its data in memory. Your application manages persistence, rotation across processes, and propagation timing.

`StaticKeyring` lets you publish additional keys and point one purpose directly to another. To share a federation signer with another purpose, configure the binding explicitly with either keyring. A custom keyring can use `KeySelectionContext` to pick a key by issuer, subject, Trust Mark type, or other information supplied by the application.

## Application algorithms

Use `createJwsAlgorithmRegistry` to add an algorithm and its public key format. Share the registry across your host, keyring and standalone operations. Select the permitted Federation Entity Key algorithms with `allowedFederationAlgorithms`. Protocol roles apply their own algorithm settings. See the [complete custom crypto example](https://oidfed.com/docs/examples/custom-crypto).

## Adapters and support

```sh
pnpm add jose
```

```ts
import { createJoseEngine } from "@oidfed/crypto/jose";
const engine = createJoseEngine();
```

JOSE uses global Web Crypto to verify signatures. If you pass an implementation to the JOSE adapter, it uses that implementation for hashing and randomness. Use `/web` or provide your own `CryptoEngine` if you need to supply the entire backend.

The test suite covers Node, Bun, Deno, workerd, Electron, and Chromium. React Native and native keystore integrations are outside that test matrix. See the [API reference](https://oidfed.com/docs/api/crypto) and [adapter recipes](https://oidfed.com/docs/api/crypto/adapters).
