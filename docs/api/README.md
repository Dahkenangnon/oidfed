# API reference

Each package index lists its public exports. Reference pages describe callable signatures, configuration contracts, and public class members, with short usage examples where helpful. Re-exports lead to the owning package's entry.

- [Crypto](crypto/README.md): portable crypto engines, signing custody and keyring snapshots.
- [Core](core/README.md): shared federation primitives and services.
- [Authority](authority/README.md): Trust Anchors, Intermediates, and authoritative storage.
- [Leaf](leaf/README.md): participant publication and optional hosted services.
- [OIDC/OAuth](oidc/README.md): protocol roles and federation registration.
- [Wallet](wallet/README.md): federation trust for wallet participants and artifacts.

## Reading a result

The API's declared return type matters. `Result<T>` uses `ok` and exposes either `value` or `error`. Trust-chain validation uses `valid` and validation errors. Metadata parsers use `success`. Constructors and assertion-style configuration helpers can throw. Do not treat every API as returning the same error shape.

```ts
import { entityId, discoverEntity, type TrustAnchorSet } from "@oidfed/core";

export async function findHarbor(anchors: TrustAnchorSet) {
  const result = await discoverEntity(entityId("https://harbor.example"), anchors);
  if (!result.ok) return result;
  // Keep the authenticated discovery result for a subsequent protocol operation.
  return result;
}
```

Signature blocks describe contracts and may refer to neighboring named types; they are not standalone programs. Examples use public package imports. A function parameter in an example is a host-supplied dependency, such as pinned anchor keys or a durable store. Network examples use fictional addresses and need your deployment's URLs and transport configuration.

## From a call to a workflow

The [feature guides](../features/README.md) explain how to select actors, configure trust, connect calls, and maintain the resulting state. A successful schema parse checks shape; a decoded JWT is still unverified; a valid chain alone does not grant application access. Use the operation that establishes the evidence required by your workflow.
