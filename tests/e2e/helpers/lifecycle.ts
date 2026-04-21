import { afterAll, beforeAll } from "vitest";
import type { TopologyDefinition } from "../topologies/types.js";
import { type FederationTestBed, launchFederation } from "./launcher.js";

export function useFederation(topology: TopologyDefinition) {
	let testBed: FederationTestBed;

	beforeAll(async () => {
		testBed = await launchFederation(topology);
	});

	afterAll(async () => {
		await testBed?.close();
	});

	return () => testBed;
}
