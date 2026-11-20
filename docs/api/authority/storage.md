# Authority storage

Trust Anchors and Intermediates take `storage: FederationStorage` from [the core storage API](../core/storage.md). The authority requires subordinate reads for its Fetch and List endpoints. Lifecycle methods use the subordinate write repository and a serializable transaction. When event capture is configured, registration changes and their events commit together.

## `SubordinateRecord`

A subordinate's Entity Identifier, public Federation Entity Keys, optional statement claims, and finite creation and update NumericDates.

## `SubordinateRecordUpdate`

Changes to mutable claims. Pass the update NumericDate to the repository.

## `ListFilter`

Filters applied before paging the live subordinate list.

## `ListPageOptions`

An inclusive starting cursor, a page limit, and optional update bounds.

## `ListPage`

Records in Entity Identifier order and, when more data is available, the first unreturned position.

## `SubordinateEventAnnotations`

Description and information URI supplied to each event recorded by a managed operation.

Use `registerSubordinate`, `updateSubordinate`, and `revokeSubordinate` on the host. These methods validate publication claims, supply the host's timestamps, and record events when enabled. Use direct repository writes for controlled imports or tests. See the [adapter guide](../../features/11.6.storage-adapters.md) for requirements by feature.
