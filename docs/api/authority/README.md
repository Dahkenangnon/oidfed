# `@oidfed/authority` API

[API reference](../README.md)

Every root export is listed below. Re-exported Trust Mark contracts link to their owning core reference. Class entries include constructors and library-defined public members, including static callable properties and readonly getters. The four error classes also inherit the runtime’s `Error` API.

## Trust Marks

| API | Kind |
|---|---|
| [`TrustMarkListOptions`](../core/marks.md#trustmarklistoptions) | Interface; from @oidfed/core |
| [`TrustMarkListPage`](../core/marks.md#trustmarklistpage) | Interface; from @oidfed/core |
| [`TrustMarkRecord`](../core/marks.md#trustmarkrecord) | Interface; from @oidfed/core |
| [`TrustMarkStorage`](../core/marks.md#trustmarkstorage) | Interface; from @oidfed/core |

## Federation hosts

| API | Kind |
|---|---|
| [`AuthorityClientKeyProvider`](hosts.md#authorityclientkeyprovider) | Interface |
| [`AuthorityConfig`](hosts.md#authorityconfig) | Interface |
| [`AuthorityServer`](hosts.md#authorityserver) | Interface |
| [`ExtendedListingConfig`](hosts.md#extendedlistingconfig) | Interface |
| [`ExtendedListingFilterContext`](hosts.md#extendedlistingfiltercontext) | Interface |
| [`ExtendedListingRequestFilter`](hosts.md#extendedlistingrequestfilter) | Interface |
| [`ExtendedSubordinateListingOptions`](hosts.md#extendedsubordinatelistingoptions) | Type |
| [`ExtendedSubordinateListingParams`](hosts.md#extendedsubordinatelistingparams) | Type |
| [`ExtendedSubordinateListingResult`](hosts.md#extendedsubordinatelistingresult) | Interface |
| [`FederationHandler`](hosts.md#federationhandler) | Type |
| [`Intermediate`](hosts.md#intermediate) | Class |
| [`InvalidAuthorityConfig`](hosts.md#invalidauthorityconfig) | Class |
| [`InvalidMetadata`](hosts.md#invalidmetadata) | Class |
| [`InvalidSubordinateRecord`](hosts.md#invalidsubordinaterecord) | Class |
| [`InvalidSubordinateStatementShape`](hosts.md#invalidsubordinatestatementshape) | Class |
| [`Middleware`](hosts.md#middleware) | Type |
| [`TrustAnchor`](hosts.md#trustanchor) | Class |

## Storage and transactions

| API | Kind |
|---|---|
| [`ListFilter`](storage.md#listfilter) | Interface |
| [`ListPage`](storage.md#listpage) | Interface |
| [`ListPageOptions`](storage.md#listpageoptions) | Interface |
| [`MemoryStorageAdapter`](storage.md#memorystorageadapter) | Class |
| [`MemoryStorageAdapterOptions`](storage.md#memorystorageadapteroptions) | Interface |
| [`StorageAdapter`](storage.md#storageadapter) | Interface |
| [`StorageReadSnapshot`](storage.md#storagereadsnapshot) | Interface |
| [`StorageTransaction`](storage.md#storagetransaction) | Interface |
| [`SubordinateEventAnnotations`](storage.md#subordinateeventannotations) | Interface |
| [`SubordinateEventStorage`](storage.md#subordinateeventstorage) | Interface |
| [`SubordinateRecord`](storage.md#subordinaterecord) | Interface |
| [`SubordinateRecordUpdate`](storage.md#subordinaterecordupdate) | Type |
| [`SubordinateStorage`](storage.md#subordinatestorage) | Interface |

