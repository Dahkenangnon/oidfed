# Authority storage

Trust Anchors and Intermediates take `storage: FederationStorage` from [the core storage API](../core/storage.md). The authority requires subordinate reads for its Fetch and List endpoints. Lifecycle methods use the subordinate write repository and a serializable transaction. When event capture is configured, registration changes and their events commit together.

## `SubordinateRecord`

Import [`SubordinateRecord`](../core/storage.md#subordinaterecord) from `@oidfed/core`.

## `SubordinateRecordUpdate`

Import [`SubordinateRecordUpdate`](../core/storage.md#subordinaterecordupdate) from `@oidfed/core`.

## `ListFilter`

Import [`ListFilter`](../core/storage.md#listfilter) from `@oidfed/core`.

## `ListPageOptions`

Import [`ListPageOptions`](../core/storage.md#listpageoptions) from `@oidfed/core`.

## `ListPage`

Import [`ListPage`](../core/storage.md#listpage) from `@oidfed/core`.

## `SubordinateEventAnnotations`

Import [`SubordinateEventAnnotations`](../core/storage.md#subordinateeventannotations) from `@oidfed/core`.

Use `registerSubordinate`, `updateSubordinate`, and `revokeSubordinate` on the host. These methods validate publication claims, supply the host's timestamps, and record events when enabled. Use direct repository writes for controlled imports or tests. See the [adapter guide](../../features/11.6.storage-adapters.md) for requirements by feature.
