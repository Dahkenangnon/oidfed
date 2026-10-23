import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";
import {
	entityId,
	fetchExtendedSubordinatesList,
	fetchSubordinateEvents,
	fetchSubordinateStatement,
	InternalErrorCode,
	JwkSigner,
	MediaType,
	signEntityStatement,
} from "@oidfed/core";
import express from "express";
import { describe, expect, it } from "vitest";
import { getAuthorityEntity } from "../helpers/launcher.js";
import { useFederation } from "../helpers/lifecycle.js";
import { singleAnchorTopology } from "../topologies/single-anchor.js";

const topology = {
	...singleAnchorTopology,
	name: "subordinate-events",
	entities: singleAnchorTopology.entities.map((entity) =>
		entity.role === "trust-anchor"
			? {
					...entity,
					metadata: {
						...entity.metadata,
						federation_entity: {
							...entity.metadata.federation_entity,
							federation_subordinate_events_endpoint: "https://ta.ofed.test/history?version=1",
							federation_subordinate_events_endpoint_auth_methods: ["none", "private_key_jwt"],
						},
					},
				}
			: entity,
	),
};

describe("Subordinate Events over HTTPS", () => {
	const bed = useFederation(topology);
	it("blocks redirect destinations and assertion forwarding without changing legacy GET redirects", async () => {
		const { entities, server } = bed();
		const authority = getAuthorityEntity(entities, "https://ta.ofed.test");
		const issuer = entityId(`https://ta.ofed.test:${server.port}`);
		const subject = entityId(`https://rp.ofed.test:${server.port}`);
		const redirectOrigin = `https://redirect.ofed.test:${server.port}`;
		const app = express();
		let received = 0;
		let forwardedAssertion = false;
		app.use(express.urlencoded({ extended: false }));
		app.all("/capture", (req, res) => {
			received++;
			forwardedAssertion ||= Boolean(req.body?.client_assertion);
			res.status(500).end();
		});
		app.get("/legacy-list", (_req, res) => res.redirect(307, "/list-final"));
		app.get("/list-final", (_req, res) =>
			res
				.setHeader("Content-Type", MediaType.Json)
				.end(JSON.stringify({ immediate_subordinate_entities: [{ id: subject }] })),
		);
		app.get("/legacy-fetch", (_req, res) => res.redirect(308, "/fetch-final"));
		app.get("/fetch-final", async (_req, res) =>
			res
				.setHeader("Content-Type", MediaType.EntityStatement)
				.end(await authority.server.getSubordinateStatement(subject)),
		);
		server.addEntity(redirectOrigin, app);
		server.addEntity(`https://capture.ofed.test:${server.port}`, app);
		server.addEntity(`https://127.0.0.1:${server.port}`, app);
		const httpTarget = createServer((req, res) => {
			received++;
			let body = "";
			req.on("data", (chunk) => {
				body += chunk;
			});
			req.on("end", () => {
				forwardedAssertion ||= new URLSearchParams(body).has("client_assertion");
				res.writeHead(500).end();
			});
		});
		await new Promise<void>((resolve) => httpTarget.listen(0, "127.0.0.1", resolve));
		try {
			const address = httpTarget.address();
			if (!address || typeof address === "string")
				throw new Error("HTTP capture server did not bind");
			const destinations = [
				`${redirectOrigin}/capture`,
				`https://capture.ofed.test:${server.port}/capture`,
				`https://127.0.0.1:${server.port}/capture`,
				`http://127.0.0.1:${address.port}/capture`,
			];
			for (const status of [301, 302, 303, 307, 308]) {
				for (const [index, target] of destinations.entries()) {
					const path = `/redirect/${status}/${index}`;
					let redirectRequests = 0;
					app.all(path, (_req, res) => {
						redirectRequests++;
						res.redirect(status, target);
					});
					for (const authenticated of [false, true]) {
						const url = new URL(path, redirectOrigin);
						const result = await fetchSubordinateEvents(url.toString(), subject, {
							issuer,
							issuerJwks: { keys: [authority.keys.public] },
							...(authenticated ? { clientAssertion: "synthetic-assertion" } : {}),
						});
						expect(result).toMatchObject({
							ok: false,
							error: {
								code: InternalErrorCode.Network,
								description: expect.stringContaining(`HTTP ${status} from `),
							},
						});
						expect(redirectRequests).toBe(authenticated ? 2 : 1);
						expect(received).toBe(0);
						expect(forwardedAssertion).toBe(false);
					}
				}
			}
			const listing = await fetchExtendedSubordinatesList(`${redirectOrigin}/legacy-list`);
			expect(listing.ok, listing.ok ? "verified listing" : listing.error.description).toBe(true);
			if (listing.ok)
				expect(listing.value.immediate_subordinate_entities).toEqual([{ id: subject }]);
			const statement = await fetchSubordinateStatement(`${redirectOrigin}/legacy-fetch`, subject);
			expect(statement.ok, statement.ok ? "fetched statement" : statement.error.description).toBe(
				true,
			);
			if (statement.ok) expect(statement.value.split(".")).toHaveLength(3);
		} finally {
			await new Promise<void>((resolve, reject) =>
				httpTarget.close((error) => (error ? reject(error) : resolve())),
			);
		}
	});

	it("retrieves signed history through the core client and the actual CLI", async () => {
		const { entities, server } = bed();
		const authority = getAuthorityEntity(entities, "https://ta.ofed.test");
		const issuer = entityId(`https://ta.ofed.test:${server.port}`);
		const subject = entityId(`https://rp.ofed.test:${server.port}`);
		const endpoint = `https://ta.ofed.test:${server.port}/history?version=1`;
		await authority.server.recordSubordinateEvents(subject, [
			{ iat: -0.5, event: "operator.review", information_uri: "http://info.example/#review" },
		]);
		const result = await fetchSubordinateEvents(endpoint, subject, {
			issuer,
			issuerJwks: { keys: [authority.keys.public] },
		});
		expect(result.ok).toBe(true);
		if (!result.ok) throw new Error(result.error.description);
		expect(result.value.federation_registration_events).toEqual([
			{ iat: -0.5, event: "operator.review", information_uri: "http://info.example/#review" },
		]);
		const directory = await mkdtemp(join(tmpdir(), "oidfed-events-cli-"));
		try {
			const jwksFile = join(directory, "issuer.json");
			await writeFile(jwksFile, JSON.stringify({ keys: [authority.keys.public] }));
			// Match the parent HTTPS harness's local DNS routing in the CLI process.
			const preload = join(directory, "local-dns.mjs");
			await writeFile(
				preload,
				`import { Agent, setGlobalDispatcher } from ${JSON.stringify(pathToFileURL(resolve("node_modules/undici/index.js")).href)};
setGlobalDispatcher(new Agent({ connect: { lookup(_host, _options, callback) { callback(null, [{ address: "127.0.0.1", family: 4 }]); } } }));`,
			);
			const caDirectory = (await readFile(resolve(".certs/ca-path.txt"), "utf8")).trim();
			const { stdout } = await promisify(execFile)(
				process.execPath,
				[
					"--import",
					pathToFileURL(preload).href,
					resolve("tools/cli/dist/bin.js"),
					"--json",
					"subordinate-events",
					issuer,
					subject,
					"--jwks-file",
					jwksFile,
				],
				{ env: { ...process.env, NODE_EXTRA_CA_CERTS: join(caDirectory, "rootCA.pem") } },
			);
			expect(JSON.parse(stdout)).toMatchObject({
				iss: issuer,
				sub: subject,
				federation_registration_events: result.value.federation_registration_events,
			});
		} finally {
			await rm(directory, { recursive: true, force: true });
		}
	});

	it("retains history after explicit revocation and reports unknown subjects", async () => {
		const { entities, server } = bed();
		const authority = getAuthorityEntity(entities, "https://ta.ofed.test");
		const subject = entityId(`https://rp2.ofed.test:${server.port}`);
		const issuer = entityId(`https://ta.ofed.test:${server.port}`);
		const endpoint = `https://ta.ofed.test:${server.port}/history?version=1`;
		const options = { issuer, issuerJwks: { keys: [authority.keys.public] } };
		await authority.server.revokeSubordinate(subject);
		const result = await fetchSubordinateEvents(endpoint, subject, options);
		expect(result.ok).toBe(true);
		if (result.ok)
			expect(result.value.federation_registration_events.at(-1)?.event).toBe("revocation");
		const missing = await fetchSubordinateEvents(
			endpoint,
			entityId("https://unknown.example"),
			options,
		);
		expect(missing.ok).toBe(false);
		if (!missing.ok) expect(missing.error.code).toBe("not_found");
	});

	it("accepts authenticated POST with a separate client and requested subject", async () => {
		const { entities, server } = bed();
		const authority = getAuthorityEntity(entities, "https://ta.ofed.test");
		const client = entities.get("https://rp.ofed.test");
		if (!client) throw new Error("Client fixture missing");
		const issuer = entityId(`https://ta.ofed.test:${server.port}`);
		const clientId = entityId(`https://rp.ofed.test:${server.port}`);
		const subject = entityId(`https://op.ofed.test:${server.port}`);
		const now = Math.floor(Date.now() / 1000);
		const assertion = await signEntityStatement(
			{
				iss: clientId,
				sub: clientId,
				aud: issuer,
				iat: now,
				exp: now + 60,
				jti: crypto.randomUUID(),
			},
			new JwkSigner(client.keys.signing),
			{ typ: "JWT" },
		);
		const result = await fetchSubordinateEvents(
			`https://ta.ofed.test:${server.port}/history?version=1`,
			subject,
			{
				issuer,
				issuerJwks: { keys: [authority.keys.public] },
				clientAssertion: assertion,
			},
		);
		expect(result.ok).toBe(true);
		if (result.ok) expect(result.value.sub).toBe(subject);
	});
});
