/** @oidfed/leaf — Leaf entity: EC serving and trust chain discovery. */

export type { DiscoveryResult } from "@oidfed/core";
export { discoverEntity } from "./discovery.js";
export {
	createLeafEntity,
	type LeafConfig,
	type LeafEntity,
} from "./entity-configuration.js";
export {
	createLeafHandler,
	type FederationHandler,
} from "./handler.js";
