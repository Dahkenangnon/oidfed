import { decodeEntityStatement, entityId, fetchExtendedSubordinatesList, isOk } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { getAuthorityEntity } from "../helpers/launcher.js";
import { useFederation } from "../helpers/lifecycle.js";
import { singleAnchorTopology } from "../topologies/single-anchor.js";

describe("Extended Subordinate Listing endpoint", () => {
	const getTestBed = useFederation(singleAnchorTopology);

	it("core client follows opaque cursors and preserves empty claims over HTTPS", async () => {
		const { server } = getTestBed();
		const endpoint = `https://ta.ofed.test:${server.port}/federation_extended_list`;
		const ids: string[] = [];
		let from: string | undefined;
		for (let page = 0; page < 4; page++) {
			const result = await fetchExtendedSubordinatesList(endpoint, {
				limit: 1,
				claims: [],
				...(from === undefined ? {} : { from }),
			});
			expect(result.ok).toBe(true);
			if (!result.ok) throw new Error(result.error.description);
			for (const entry of result.value.immediate_subordinate_entities) {
				expect(Object.keys(entry)).toEqual(["id"]);
				ids.push(entry.id);
			}
			from = result.value.next;
			if (ids.length < 3) expect(typeof from).toBe("string");
			if (from === undefined) break;
		}
		expect(ids).toEqual(
			[
				`https://op.ofed.test:${server.port}`,
				`https://rp.ofed.test:${server.port}`,
				`https://rp2.ofed.test:${server.port}`,
			].sort(),
		);
		const missing = await fetchExtendedSubordinatesList(endpoint, { from: "unknown +/=" });
		expect(missing.ok).toBe(false);
		if (!missing.ok) {
			expect(missing.error.code).toBe("page_not_found");
			expect(missing.error.description).toBe("Unknown continuation cursor");
		}
	});

	it("repeated mark types return the valid union across HTTPS pages", async () => {
		const { entities, server } = getTestBed();
		const authority = getAuthorityEntity(entities, "https://ta.ofed.test");
		const marks = authority.storage?.trustMarks;
		if (!marks) throw new Error("Expected authority trust mark storage");
		const now = Math.floor(Date.now() / 1000);
		const alpha = "https://marks.example/alpha";
		const beta = "https://marks.example/beta";
		const op = entityId(`https://op.ofed.test:${server.port}`);
		const rp = entityId(`https://rp.ofed.test:${server.port}`);
		const rp2 = entityId(`https://rp2.ofed.test:${server.port}`);
		for (const [subject, type, active, expiresAt] of [
			[op, alpha, true, now + 3600],
			[op, beta, true, now + 3600],
			[rp, beta, true, now + 3600],
			[rp2, alpha, true, now - 1],
			[rp2, beta, false, now + 3600],
		] as const)
			await marks.issue({
				subject,
				trustMarkType: type,
				jwt: `fixture.${subject}.${type}`,
				issuedAt: now - 60,
				active,
				expiresAt,
			});
		try {
			const endpoint = `https://ta.ofed.test:${server.port}/federation_extended_list`;
			const first = await fetchExtendedSubordinatesList(endpoint, {
				limit: 1,
				claims: [],
				trustMarked: false,
				trustMarkType: [alpha, beta, beta],
			});
			expect(first.ok).toBe(true);
			if (!first.ok) throw new Error(first.error.description);
			expect(typeof first.value.next).toBe("string");
			if (first.value.next === undefined) throw new Error("Expected a continuation cursor");
			const tail = await fetchExtendedSubordinatesList(endpoint, {
				from: first.value.next,
				claims: [],
				trustMarked: false,
				trustMarkType: [alpha, beta],
			});
			expect(tail.ok).toBe(true);
			if (!tail.ok) throw new Error(tail.error.description);
			expect(
				[
					...first.value.immediate_subordinate_entities,
					...tail.value.immediate_subordinate_entities,
				].map(({ id }) => id),
			).toEqual([op, rp].sort());
			expect(tail.value.next).toBeUndefined();
			const base = `https://ta.ofed.test:${server.port}/federation_list`;
			const unfiltered = await fetch(`${base}?trust_marked=false`);
			expect(unfiltered.status).toBe(200);
			expect(await unfiltered.json()).toEqual([op, rp, rp2].sort());
			const filtered = await fetch(
				`${base}?trust_marked=false&trust_mark_type=${encodeURIComponent(alpha)}`,
			);
			expect(filtered.status).toBe(200);
			expect(await filtered.json()).toEqual([op]);
		} finally {
			await marks.revoke(alpha, op, now);
			await marks.revoke(beta, op, now);
			await marks.revoke(beta, rp, now);
			await marks.revoke(alpha, rp2, now);
		}
	});

	it("preserves fractional audit timestamps and inclusive time filters over HTTPS", async () => {
		const { entities, server } = getTestBed();
		const authority = getAuthorityEntity(entities, "https://ta.ofed.test");
		const subordinates = authority.storage?.subordinates;
		if (!subordinates) throw new Error("Expected authority subordinate storage");
		const id = entityId(`https://rp.ofed.test:${server.port}/fractional`);
		await subordinates.add({
			entityId: id,
			jwks: { keys: [] },
			createdAt: -0.5,
			updatedAt: 1500.5,
		});
		try {
			for (const updatedAfter of [-0.5, 1500.5]) {
				const result = await fetchExtendedSubordinatesList(
					`https://ta.ofed.test:${server.port}/federation_extended_list`,
					{ claims: [], updatedAfter, updatedBefore: 1500.5 },
				);
				expect(result.ok).toBe(true);
				if (!result.ok) throw new Error(result.error.description);
				expect(result.value.immediate_subordinate_entities).toEqual([
					{ id, registered: -0.5, updated: 1500.5 },
				]);
			}
		} finally {
			await subordinates.remove(id);
		}
	});

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

	it("intermediate filtering treats OP and RP entities as leaves", async () => {
		const { server } = getTestBed();
		const port = server.port;
		const endpoint = `https://ta.ofed.test:${port}/federation_extended_list`;

		const intermediateResponse = await fetch(`${endpoint}?intermediate=true`);
		expect(intermediateResponse.status).toBe(200);
		const intermediateBody = (await intermediateResponse.json()) as {
			immediate_subordinate_entities: Array<{ id: string }>;
		};
		expect(intermediateBody.immediate_subordinate_entities).toEqual([]);

		const leafResponse = await fetch(`${endpoint}?intermediate=false`);
		expect(leafResponse.status).toBe(200);
		const leafBody = (await leafResponse.json()) as {
			immediate_subordinate_entities: Array<{ id: string }>;
		};
		expect(leafBody.immediate_subordinate_entities.map(({ id }) => id).sort()).toEqual(
			[
				`https://op.ofed.test:${port}`,
				`https://rp.ofed.test:${port}`,
				`https://rp2.ofed.test:${port}`,
			].sort(),
		);
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
		expect(first).toBeDefined();
		if (!first) throw new Error("Expected at least one subordinate entity");
		const jwt = first.subordinate_statement;
		expect(jwt).toBeTruthy();
		if (!jwt) throw new Error("Expected a subordinate statement JWT");
		expect(jwt.split(".")).toHaveLength(3);
	});

	it("limit + from paginate through the full set in deterministic order", async () => {
		const { server } = getTestBed();
		const port = server.port;
		const endpoint = `https://ta.ofed.test:${port}/federation_extended_list`;

		const pageA = (await (await fetch(`${endpoint}?limit=2`)).json()) as {
			immediate_subordinate_entities: Array<{ id: string }>;
			next?: string;
		};
		expect(pageA.immediate_subordinate_entities.length).toBe(2);
		expect(pageA.next).toBeTruthy();

		const pageB = (await (
			await fetch(`${endpoint}?limit=2&from=${encodeURIComponent(pageA.next as string)}`)
		).json()) as {
			immediate_subordinate_entities: Array<{ id: string }>;
			next?: string;
		};
		expect(pageB.next).toBeUndefined();

		const concatenated = [
			...pageA.immediate_subordinate_entities.map((e) => e.id),
			...pageB.immediate_subordinate_entities.map((e) => e.id),
		];
		const sorted = [...concatenated].sort();
		expect(concatenated).toEqual(sorted);
	});

	it("from pointing at a non-subordinate returns 404 page_not_found", async () => {
		const { server } = getTestBed();
		const port = server.port;
		const res = await fetch(
			`https://ta.ofed.test:${port}/federation_extended_list?from=${encodeURIComponent("https://does-not-exist.ofed.test")}`,
		);
		expect(res.status).toBe(404);
		expect(res.headers.get("content-type")).toContain("application/json");
		const body = (await res.json()) as { error: string };
		expect(body.error).toBe("page_not_found");
	});

	it("listSubordinatesExtended server API returns paginated entries with audit timestamps", async () => {
		const { entities } = getTestBed();
		const taInstance = getAuthorityEntity(entities, "https://ta.ofed.test");
		const ta = taInstance.server;

		const result = await ta.listSubordinatesExtended({ auditTimestamps: true, limit: 100 });
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.value.immediate_subordinate_entities.length).toBeGreaterThan(0);
		for (const entry of result.value.immediate_subordinate_entities) {
			expect(typeof entry.registered).toBe("number");
		}
	});
});
