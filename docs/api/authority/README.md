# `@oidfed/authority` API

[API reference](../README.md)

Every root export is listed below. Class entries include constructors and library-defined public members, including static callable properties and readonly getters. `InvalidAuthorityConfig` inherits the runtime’s `Error` API.

## Trust Marks

Import [`TrustMarkListOptions`](../core/marks.md#trustmarklistoptions), [`TrustMarkListPage`](../core/marks.md#trustmarklistpage), and [`TrustMarkRecord`](../core/marks.md#trustmarkrecord) from `@oidfed/core`.

## Federation hosts

| API | Kind |
|---|---|
| [`AuthorityClientKeyProvider`](hosts.md#authorityclientkeyprovider) | Interface |
| [`AuthorityConfig`](hosts.md#authorityconfig) | Interface |
| [`ExtendedListingConfig`](hosts.md#extendedlistingconfig) | Interface |
| [`ExtendedListingFilterContext`](hosts.md#extendedlistingfiltercontext) | Interface |
| [`ExtendedListingRequestFilter`](hosts.md#extendedlistingrequestfilter) | Interface |
| [`ExtendedSubordinateListingOptions`](hosts.md#extendedsubordinatelistingoptions) | Type |
| [`ExtendedSubordinateListingResult`](hosts.md#extendedsubordinatelistingresult) | Interface |
| [`FederationHandler`](hosts.md#federationhandler) | Type |
| [`Intermediate`](hosts.md#intermediate) | Class |
| [`IntermediateConfig`](hosts.md#intermediateconfig) | Interface |
| [`InvalidAuthorityConfig`](hosts.md#invalidauthorityconfig) | Class |
| [`TrustAnchor`](hosts.md#trustanchor) | Class |

## Storage

Import the following types, `FederationStorage`, and `MemoryFederationStorage` from [`@oidfed/core`](../core/storage.md).

| API | Kind |
|---|---|
| [`ListFilter`](storage.md#listfilter) | Interface |
| [`ListPage`](storage.md#listpage) | Interface |
| [`ListPageOptions`](storage.md#listpageoptions) | Interface |
| [`SubordinateEventAnnotations`](storage.md#subordinateeventannotations) | Interface |
| [`SubordinateRecord`](storage.md#subordinaterecord) | Type |
| [`SubordinateRecordUpdate`](storage.md#subordinaterecordupdate) | Type |

