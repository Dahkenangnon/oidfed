/** @oidfed/leaf — Leaf entity: EC serving and trust chain discovery. */

export type { DiscoveryResult } from "@oidfed/core";
export { discoverEntity } from "./discovery.js";
export {
	Leaf,
	type LeafConfig,
} from "./entity-configuration.js";
