# Host adapter recipes

Implement `Signer` when only key custody changes. Implement `CryptoEngine` when the host also supplies verification, hashing or secure randomness. A custom `Keyring` can select by artifact, issuer, subject, or Trust Mark type using `KeySelectionContext`. These contracts have no framework or wallet dependency.

## Choose a Federation signing key by artifact

For one Federation key, pass `new StaticKeyring({ signers: { federation: signer } })` to the host's crypto configuration. Omit the artifact policy to use the Federation algorithm allowlist for every operation.

An Entity Configuration and a Historical Keys response can have the same issuer and subject. If they use separate signing bindings, select the binding by `context.artifact`. A binding supplies its signer and public keys together. For artifacts verified against the issuer's Entity Configuration, `federationEntry()` also checks that the selected key matches a verification key in that configuration's Federation JWKS. Trust Mark Delegations use the owner keys that the Trust Anchor publishes for the mark type.

<!-- oidfed-example -->
```ts
import { type Keyring, type Signer, StaticKeyring } from "@oidfed/crypto";
import type { BoundFederationOptions } from "@oidfed/core";

export function federationBindings(configuration: Signer, historical: Signer) {
  const custody = new StaticKeyring({
    signers: { federation: configuration, historical },
    additionalPublishedKeys: {
      federation: [historical.publicJwk],
      historical: [configuration.publicJwk],
    },
  });
  const keyring: Keyring = {
    entry(purpose, context) {
      const useHistorical = purpose === "federation" && context?.artifact === "historical-keys";
      return custody.entry(useHistorical ? "historical" : purpose, context);
    },
  };
  const options: BoundFederationOptions = {
    allowedFederationAlgorithms: ["ES256", "PS256"],
    allowedAlgorithmsForArtifact(artifact) {
      return artifact === "historical-keys" ? ["PS256"] : ["ES256"];
    },
  };
  return { keyring, options };
}
```

This example expects an ES256 configuration signer and a PS256 Historical Keys signer. Each callback result narrows the Federation allowlist. Return an empty array to deny the operation. Keep callbacks synchronous and stable for the lifetime of the configured host. Create a new host when policy changes require fresh evaluation of cached Resolve evidence.

For rollover, add the next key to the Entity Configuration, refresh Leaf's cached configuration when applicable, and allow peers time to fetch it before switching the signing binding. Leaf checks the last unexpired configuration during a refresh. An Authority that generates configurations on demand checks its Entity Configuration keyring binding.

When your application publishes a retained Entity Configuration outside oidfed, set `crypto.readPublishedFederationJwks(issuer)` to return the trusted Federation JWKS from the current publication. Read it from your serving state so the check follows the same revision as the published JWT. If that state is unavailable, let the reader fail. oidfed will stop the signing operation. The reader does not need access to private keys.

For a custom `signed_jwks_uri` handler, supply the artifact when selecting the signer and when signing. The payload contains the published protocol public keys. The JWT is signed by the issuer's Federation key.

<!-- oidfed-example -->
```ts
import { type CryptoContext, type EntityId, type FederationOptions, type JWKSet,
  federationEntry, federationSigningOptions, JwtTyp, nowSeconds, signEntityStatement } from "@oidfed/core";

export async function signProtocolKeys(
  crypto: CryptoContext, options: FederationOptions, issuer: EntityId, owner: EntityId, keys: JWKSet,
) {
  const artifact = "signed-protocol-jwks";
  const entry = await federationEntry(crypto, { artifact, issuer, subject: owner });
  return signEntityStatement(
    { iss: issuer, sub: owner, iat: nowSeconds(options.clock), keys: keys.keys },
    entry,
    { ...federationSigningOptions(options, artifact), typ: JwtTyp.JwkSet },
  );
}
```

Consumers use `verifySignedJwkSet()` for protocol keys and `verifyHistoricalKeysResponse()` for Historical Keys. Both JWTs have the type `jwk-set+jwt`. Each verifier applies the policy for the operation it performs. For the generic signing and verification APIs, supply `artifact` explicitly whenever a policy callback is configured.

## Opaque key handles

Capture a versioned key handle, its public JWK and algorithm together. A signing closure must continue using that captured handle after rotation. Export only the public key. Make sure its `kid` identifies this immutable binding and keep algorithm/usage metadata consistent.

```ts
import { derToJws, type Signer, type SigningPublicJwk, assertSigningPublicJwk, toPublicJwk } from "@oidfed/crypto";

function createP256Signer(
  publicJwk: SigningPublicJwk,
  signWithCapturedHandle: (input: Uint8Array) => Promise<Uint8Array>,
): Signer {
  if (publicJwk.alg !== "ES256") throw new Error("Expected an ES256 binding");
  return {
    publicJwk: assertSigningPublicJwk(toPublicJwk(publicJwk)),
    async sign(input) {
      // This particular host callback returns ASN.1 DER, not R || S.
      return derToJws(await signWithCapturedHandle(input), "ES256");
    },
  };
}
```

Use `derToJws` only for a backend that actually returns DER; Web Crypto ECDSA already returns JWS-compatible bytes. Native integrations must test their real handle lifetime, supported algorithms, cancellation behavior and signature representation. No native SDK adapter or React Native fixture is shipped here.

## Remote P-256 signing with AWS KMS

The application owns SDK installation, credentials, retry policy and authorization. Resolve a versioned KMS key ARN and obtain/validate its public JWK before constructing this signer. Use a digest request so large JWS inputs do not hit KMS's raw-message limit.

```ts
import { SignCommand, type KMSClient } from "@aws-sdk/client-kms";
import { derToJws, type CryptoEngine, type Signer, type SigningPublicJwk, assertSigningPublicJwk, toPublicJwk } from "@oidfed/crypto";

export function kmsP256Signer(
  kms: KMSClient, engine: CryptoEngine, keyArn: string, publicJwk: SigningPublicJwk,
): Signer {
  if (publicJwk.alg !== "ES256") throw new Error("Expected ES256");
  return {
    publicJwk: assertSigningPublicJwk(toPublicJwk(publicJwk)),
    async sign(input) {
      const digest = await engine.digest("SHA-256", input);
      if (digest.length !== 32) throw new Error("Invalid digest output");
      const result = await kms.send(new SignCommand({
        KeyId: keyArn,
        SigningAlgorithm: "ECDSA_SHA_256",
        MessageType: "DIGEST",
        Message: digest,
      }));
      if (!result.Signature) throw new Error("KMS did not return a signature");
      return derToJws(result.Signature, "ES256");
    },
  };
}
```

The package does not import the AWS SDK. Check the service's returned key identity and your account's policies when establishing the binding. A mutable KMS alias is insufficient as an immutable signing handle. See [KMS Sign](https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html) for algorithm and message semantics.

## Implement an application algorithm

The [complete custom crypto example](../../examples/custom-crypto.ts) delegates built-in operations to Web Crypto, registers a private-use JOSE identifier and public JWK format, and binds an opaque signing handle. For a deployment, use the identifier, key representation and signature encoding defined by its assurance profile. Keep the registry fixed for the lifetime of the configured context. Registering an algorithm supplies validation rules. The engine and signer supply the actual cryptography.

## Engine implementations

An engine must advertise only the algorithms its integration is configured to handle, validate public keys using `assertVerificationKey`, return literal booleans from verification, and reject backend failures instead of converting them into success or signature mismatch. It must return fresh digest bytes of the correct length and exactly the requested number of cryptographically secure random bytes. Do not use `Math.random` for cryptographic randomness.

Use the original signing-input bytes without JSON reserialization. An engine that needs compact serialization reconstructs it from those ASCII bytes, a dot and the base64url-encoded signature. `JwsVerifyInput` has no `compact` field. Native key handles remain inside the signer or engine implementation. A host verifier supplies the algorithm from the same protected header, applies its protocol policy and accepts only a literal `true` result.
