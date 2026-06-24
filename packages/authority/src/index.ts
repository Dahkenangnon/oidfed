export * from "./endpoints/index.js";

export {
	InvalidAuthorityConfig,
	InvalidMetadata,
	InvalidSubordinateRecord,
	InvalidSubordinateStatementShape,
} from "./errors.js";
export {
	compose,
	type FederationHandler,
	type Middleware,
} from "./handler.js";
export { rotateKey, rotateKeyCompromise } from "./keys/index.js";
export {
	type AuthorityConfig,
	type ExtendedListInProcessParams,
	type ExtendedListInProcessResult,
	Intermediate,
	TrustAnchor,
} from "./server.js";
export {
	type ListFilter,
	type ListPage,
	type ListPageOptions,
	MemoryStorageAdapter,
	type MemoryStorageAdapterOptions,
	type StorageAdapter,
	type StorageTransaction,
	type SubordinateRecord,
	type SubordinateRecordUpdate,
	type SubordinateStorage,
	type TrustMarkListOptions,
	type TrustMarkListPage,
	type TrustMarkRecord,
	type TrustMarkStorage,
	validateSubordinateRecord,
} from "./storage/index.js";
export {
	assertCritShape,
	assertMetadataPolicyCritShape,
	assertMetadataPolicyShape,
	assertMetadataValuesNotNull,
	assertSubordinateStatementShape,
	FEDERATION_ENTITY_OPERATIONAL_FIELDS,
	isFederationEntityOperationalField,
	SUBORDINATE_STATEMENT_FORBIDDEN_TOP_LEVEL_CLAIMS,
	sanitizeSubordinateMetadata,
} from "./utils/subordinate-statement-shape.js";
