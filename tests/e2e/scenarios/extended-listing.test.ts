import type { AuthorityServer } from "@oidfed/authority";
import { decodeEntityStatement, isOk } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { getEntity } from "../helpers/launcher.js";
import { useFederation } from "../helpers/lifecycle.js";
import { singleAnchorTopology } from "../topologies/single-anchor.js";

describe("Extended Subordinate Listing endpoint", () => {
	const getTestBed = useFederation(singleAnchorTopology);

	it("authority publishes federation_extended_list_endpoint in its Entity Configuration", async () => {
		const { server } = getTestBed();
		const port = server.port;
		const ec = await fetch(`https://ta.ofed.test:${port}/.well-known/openid-federation`).then((r) =>
			r.text(),
		);
		const decoded = decodeEntityStatement(ec);
		expect(isOk(decoded)).toBe(true);
		if (isOk(decoded)) {
			const md = decoded.value.payload.metadata as {
				federation_entity?: { federation_extended_list_endpoint?: string };
			};
			expect(md.federation_entity?.federation_extended_list_endpoint).toBeTruthy();
		}
	});

	it("GET /federation_extended_list returns immediate_subordinate_entities", async () => {
		const { server } = getTestBed();
		const port = server.port;
		const res = await fetch(`https://ta.ofed.test:${port}/federation_extended_list`);
		expect(res.status).toBe(200);
		expect(res.headers.get("content-type")).toContain("application/json");
		const body = (await res.json()) as {
			immediate_subordinate_entities: Array<{ id: string }>;
		};
		expect(Array.isArray(body.immediate_subordinate_entities)).toBe(true);
		const ids = body.immediate_subordinate_entities.map((e) => e.id);
		expect(ids).toContain(`https://op.ofed.test:${port}`);
		expect(ids).toContain(`https://rp.ofed.test:${port}`);
		expect(ids).toContain(`https://rp2.ofed.test:${port}`);
	});

	it("audit_timestamps=true returns registered + updated per entity", async () => {
		const { server } = getTestBed();
		const port = server.port;
		const res = await fetch(
			`https://ta.ofed.test:${port}/federation_extended_list?audit_timestamps=true`,
		);
		const body = (await res.json()) as {
			immediate_subordinate_entities: Array<{
				id: string;
				registered: number;
				updated: number;
			}>;
		};
		for (const entry of body.immediate_subordinate_entities) {
			expect(typeof entry.registered).toBe("number");
			expect(typeof entry.updated).toBe("number");
			expect(entry.registered).toBeGreaterThan(0);
		}
	});

	it("claims=subordinate_statement returns signed subordinate statement JWTs", async () => {
		const { server } = getTestBed();
		const port = server.port;
		const res = await fetch(
			`https://ta.ofed.test:${port}/federation_extended_list?claims=subordinate_statement`,
		);
		const body = (await res.json()) as {
			immediate_subordinate_entities: Array<{ id: string; subordinate_statement?: string }>;
		};
		const first = body.immediate_subordinate_entities[0];
		expect(first).toBeDefined();
		if (!first) return;
		const jwt = first.subordinate_statement;
		expect(jwt).toBeTruthy();
		if (!jwt) return;
		expect(jwt.split(".")).toHaveLength(3);
		const decoded = decodeEntityStatement(jwt);
		expect(isOk(decoded)).toBe(true);
		if (isOk(decoded)) {
			expect(decoded.value.payload.iss).toBe(`https://ta.ofed.test:${port}`);
		}
	});

	it("bare GET defaults to claims=[subordinate_statement] (no claims= sent)", async () => {
		const { server } = getTestBed();
		const port = server.port;
		const res = await fetch(`https://ta.ofed.test:${port}/federation_extended_list`);
		const body = (await res.json()) as {
			immediate_subordinate_entities: Array<{ id: string; subordinate_statement?: string }>;
		};
		for (const entry of body.immediate_subordinate_entities) {
			expect(entry.subordinate_statement).toBeTruthy();
			expect((entry.subordinate_statement as string).split(".")).toHaveLength(3);
		}
	});

	it("accepts comma-separated claims= as a single param", async () => {
		const { server } = getTestBed();
		const port = server.port;
		const res = await fetch(
			`https://ta.ofed.test:${port}/federation_extended_list?claims=subordinate_statement,metadata`,
		);
		expect(res.status).toBe(200);
		const body = (await res.json()) as {
			immediate_subordinate_entities: Array<{ id: string; subordinate_statement?: string }>;
		};
		const first = body.immediate_subordinate_entities[0];
		expect(first?.subordinate_statement).toBeTruthy();
		expect((first?.subordinate_statement as string).split(".")).toHaveLength(3);
	});

	it("limit + from_entity_id paginate through the full set in deterministic order", async () => {
		const { server } = getTestBed();
		const port = server.port;
		const endpoint = `https://ta.ofed.test:${port}/federation_extended_list`;

		const pageA = (await (await fetch(`${endpoint}?limit=2`)).json()) as {
			immediate_subordinate_entities: Array<{ id: string }>;
			next_entity_id?: string;
		};
		expect(pageA.immediate_subordinate_entities.length).toBe(2);
		expect(pageA.next_entity_id).toBeTruthy();

		const pageB = (await (
			await fetch(
				`${endpoint}?limit=2&from_entity_id=${encodeURIComponent(pageA.next_entity_id as string)}`,
			)
		).json()) as {
			immediate_subordinate_entities: Array<{ id: string }>;
			next_entity_id?: string;
		};
		expect(pageB.next_entity_id).toBeUndefined();

		const concatenated = [
			...pageA.immediate_subordinate_entities.map((e) => e.id),
			...pageB.immediate_subordinate_entities.map((e) => e.id),
		];
		const sorted = [...concatenated].sort();
		expect(concatenated).toEqual(sorted);
	});

	it("from_entity_id pointing at a non-subordinate returns 400 entity_id_not_found", async () => {
		const { server } = getTestBed();
		const port = server.port;
		const res = await fetch(
			`https://ta.ofed.test:${port}/federation_extended_list?from_entity_id=${encodeURIComponent("https://does-not-exist.ofed.test")}`,
		);
		expect(res.status).toBe(400);
		expect(res.headers.get("content-type")).toContain("application/json");
		const body = (await res.json()) as { error: string };
		expect(body.error).toBe("entity_id_not_found");
	});

	it("listSubordinatesExtended server API returns paginated entries with audit timestamps", async () => {
		const { entities } = getTestBed();
		const taInstance = getEntity(entities, "https://ta.ofed.test");
		const ta = taInstance.server as AuthorityServer;

		const result = await ta.listSubordinatesExtended({ auditTimestamps: true, limit: 100 });
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.value.immediate_subordinate_entities.length).toBeGreaterThan(0);
		for (const entry of result.value.immediate_subordinate_entities) {
			expect(typeof entry.registered).toBe("number");
		}
	});
});
