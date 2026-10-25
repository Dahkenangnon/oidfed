import {
	createTrustAnchorSet,
	EntityCollectionService,
	entityId,
	fetchEntityCollection,
	InternalErrorCode,
	JwkSigner,
	signEntityStatement,
} from "@oidfed/core";
import express from "express";
import { describe, expect, it } from "vitest";
import { getAuthorityEntity } from "../helpers/launcher.js";
import { useFederation } from "../helpers/lifecycle.js";
import { singleAnchorTopology } from "../topologies/single-anchor.js";

describe("Entity Collection over HTTPS", () => {
	const bed = useFederation({ ...singleAnchorTopology, name: "entity-collection" });
	it("refreshes a federation and serves independent GET, POST, and authenticated POST", async () => {
		const { entities, server } = bed();
		const authority = getAuthorityEntity(entities, "https://ta.ofed.test");
		const anchor = entityId(`https://ta.ofed.test:${server.port}`);
		const receiver = entityId(`https://collection.ofed.test:${server.port}`);
		const endpoint = `${receiver}/collect?version=1`;
		const clientId = entityId(`https://rp.ofed.test:${server.port}`);
		const client = entities.get("https://rp.ofed.test");
		if (!client) throw new Error("RP fixture missing");
		const service = new EntityCollectionService({
			endpoint,
			trustAnchors: createTrustAnchorSet([
				{ entityId: anchor, jwks: { keys: [authority.keys.public] } },
			]),
			authentication: {
				methods: ["none", "private_key_jwt"],
				receiverEntityId: receiver,
				getClientFederationJwks: async (id) =>
					id === clientId ? { keys: [client.keys.public] } : undefined,
			},
		});
		const app = express();
		app.use(express.text({ type: "application/x-www-form-urlencoded" }));
		app.all("/collect", async (req, res) => {
			const response = await service.handleRequest(
				new Request(`${receiver}${req.originalUrl}`, {
					method: req.method,
					headers: { "content-type": req.get("content-type") ?? "" },
					...(req.method === "POST" ? { body: String(req.body ?? "") } : {}),
				}),
			);
			res.status(response.status);
			response.headers.forEach((value, key) => {
				res.setHeader(key, value);
			});
			res.end(await response.text());
		});
		server.addEntity(receiver, app);
		const refreshed = await service.refresh(anchor);
		expect(refreshed.ok, JSON.stringify(refreshed)).toBe(true);
		for (const method of ["GET", "POST"] as const) {
			const response = await fetchEntityCollection(
				endpoint,
				{ trustAnchor: anchor, limit: 1 },
				{ method },
			);
			expect(response.ok, JSON.stringify(response)).toBe(true);
			if (response.ok) {
				expect(response.value.entities).toHaveLength(1);
				expect(response.value.next).toBeTypeOf("string");
				const extendedParams = new URLSearchParams([
					["future_extension", "first"],
					["future_extension", "second"],
					["trust_anchor", anchor],
					["limit", "1"],
				]);
				const extendedUrl = new URL(endpoint);
				if (method === "GET")
					for (const [name, value] of extendedParams) extendedUrl.searchParams.append(name, value);
				const extendedResponse = await fetch(extendedUrl, {
					method,
					...(method === "POST" ? { body: extendedParams } : {}),
				});
				expect(extendedResponse.status).toBe(200);
				expect(await extendedResponse.json()).toMatchObject({
					entities: response.value.entities,
					next: expect.any(String),
				});
				const next = await fetchEntityCollection(endpoint, {
					trustAnchor: anchor,
					...(response.value.next ? { from: response.value.next } : {}),
				});
				expect(next.ok).toBe(true);
				if (next.ok)
					expect(
						next.value.entities.every(
							(entry) => entry.entity_id !== response.value.entities[0]?.entity_id,
						),
					).toBe(true);
			}
		}
		const now = Math.floor(Date.now() / 1000);
		const assertion = await signEntityStatement(
			{
				iss: clientId,
				sub: clientId,
				aud: receiver,
				iat: now,
				exp: now + 60,
				jti: crypto.randomUUID(),
			},
			new JwkSigner(client.keys.signing),
			{ typ: "JWT" },
		);
		expect(
			(
				await fetchEntityCollection(
					endpoint,
					{ trustAnchor: anchor },
					{ clientAssertion: assertion },
				)
			).ok,
		).toBe(true);
		expect(
			(
				await fetchEntityCollection(
					endpoint,
					{ trustAnchor: anchor },
					{ clientAssertion: assertion },
				)
			).ok,
		).toBe(false);
		expect(await fetchEntityCollection(endpoint)).toMatchObject({
			ok: true,
			value: { entities: [] },
		});
	});

	it("accepts framework-generated JSON content types for success and errors", async () => {
		const { server } = bed();
		const origin = `https://collection.ofed.test:${server.port}`;
		const app = express();
		app.get("/native-json", (_req, res) => res.json({ entities: [] }));
		app.post("/native-json", (_req, res) =>
			res.status(400).json({ error: "unsupported_claim", error_description: "Unsupported claim" }),
		);
		server.addEntity(origin, app);
		expect(await fetchEntityCollection(`${origin}/native-json`)).toEqual({
			ok: true,
			value: { entities: [] },
		});
		expect(await fetchEntityCollection(`${origin}/native-json`, {}, { method: "POST" })).toEqual({
			ok: false,
			error: { code: "unsupported_claim", description: "Unsupported claim" },
		});
	});

	it("rejects redirects before sending assertions to their destinations", async () => {
		const { server } = bed();
		const origin = `https://redirect.ofed.test:${server.port}`;
		const app = express();
		let received = 0;
		app.all("/capture", (_req, res) => {
			received++;
			res.json({ entities: [] });
		});
		for (const status of [301, 302, 303, 307, 308])
			app.all(`/redirect-${status}`, (_req, res) => res.redirect(status, `${origin}/capture`));
		server.addEntity(origin, app);
		for (const status of [301, 302, 303, 307, 308])
			for (const clientAssertion of [undefined, "synthetic-assertion"]) {
				const result = await fetchEntityCollection(
					`${origin}/redirect-${status}`,
					{},
					{ ...(clientAssertion ? { clientAssertion } : {}) },
				);
				expect(result).toMatchObject({
					ok: false,
					error: {
						code: InternalErrorCode.Network,
						description: expect.stringContaining(`HTTP ${status} from `),
					},
				});
			}
		expect(received).toBe(0);
	});
});
