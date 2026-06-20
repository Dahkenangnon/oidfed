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
	type AuthorityServer,
	createAuthorityServer,
	type ExtendedListInProcessParams,
	type ExtendedListInProcessResult,
} from "./server.js";
export {
	type ListFilter,
	type ListPage,
	type ListPageOptions,
	MemorySubordinateStore,
	MemoryTrustMarkStore,
	type SubordinateRecord,
	type SubordinateStore,
	type TrustMarkRecord,
	type TrustMarkStore,
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
