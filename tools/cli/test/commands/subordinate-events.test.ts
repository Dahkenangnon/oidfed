import {
	decodeEntityStatement,
	entityId,
	generateSigningKey,
	type HttpClient,
	JwkSigner,
	JwtTyp,
	MediaType,
	signEntityStatement,
} from "@oidfed/core";
import { Command } from "commander";
import { describe, expect, it, vi } from "vitest";
import { handler, register } from "../../src/commands/subordinate-events.js";
import { JsonFormatter } from "../../src/output/json.js";
import { createLogger } from "../../src/util/logger.js";

const issuer = entityId("https://authority.example/tenant");
const subject = entityId("https://client.example");
const endpoint = "https://events.example/history?tenant=1";

async function fixture() {
	const key = await generateSigningKey("ES256");
	const signer = new JwkSigner(key.privateKey);
	const now = Math.floor(Date.now() / 1000);
	const jwks = { keys: [key.publicKey] };
	const ec = await signEntityStatement(
		{
			iss: issuer,
			sub: issuer,
			iat: now,
			exp: now + 3600,
			jwks,
			metadata: { federation_entity: { federation_subordinate_events_endpoint: endpoint } },
		},
		signer,
	);
	const payload = {
		iss: issuer,
		sub: subject,
		iat: now,
		federation_registration_events: [{ iat: now - 1, event: "registration" }],
	};
	const jwt = await signEntityStatement(payload, signer, { typ: JwtTyp.EntityEventsStatement });
	const calls: { url: string; init: RequestInit | undefined }[] = [];
	const httpClient: HttpClient = async (url, init) => {
		calls.push({ url: String(url), init });
		return String(url).includes("/.well-known/")
			? new Response(ec, { headers: { "content-type": MediaType.EntityStatement } })
			: new Response(jwt, { headers: { "content-type": MediaType.EntityEventsStatement } });
	};
	const deps = {
		httpClient,
		formatter: new JsonFormatter(),
		logger: createLogger({ quiet: true, verbose: false }),
		readFile: vi.fn(async (_path: string) => JSON.stringify(jwks)),
	};
	return { deps, key, jwks, signer, ec, jwt, payload, calls };
}

describe("subordinate-events", () => {
	it("verifies discovery and history with pinned keys", async () => {
		const f = await fixture();
		const result = await handler({ entityId: issuer, subject, jwksFile: "pinned.json" }, f.deps);
		expect(result.ok).toBe(true);
		if (result.ok) expect(JSON.parse(result.value)).toEqual(f.payload);
		expect(f.deps.readFile).toHaveBeenCalledWith("pinned.json");
		expect(f.calls).toHaveLength(2);
		expect(f.calls[0]?.url).toBe(`${issuer}/.well-known/openid-federation`);
		expect(new URL(f.calls[1]?.url ?? "").searchParams.get("tenant")).toBe("1");
	});

	it("rejects discovery signed with an unpinned key before fetching its endpoint", async () => {
		const f = await fixture();
		const unrelated = await generateSigningKey("ES256");
		f.deps.readFile.mockResolvedValue(JSON.stringify({ keys: [unrelated.publicKey] }));
		const result = await handler({ entityId: issuer, subject, jwksFile: "pinned.json" }, f.deps);
		expect(result.ok).toBe(false);
		expect(f.calls).toHaveLength(1);
	});

	it("rejects a signed configuration naming another issuer and a history naming another subject", async () => {
		const f = await fixture();
		const decoded = decodeEntityStatement(f.ec);
		if (!decoded.ok) throw new Error(decoded.error.description);
		const raw = decoded.value.payload;
		const other = await signEntityStatement(
			{ ...raw, iss: "https://other.example", sub: "https://other.example" },
			f.signer,
		);
		const discovery = await handler(
			{ entityId: issuer, subject, jwksFile: "keys.json" },
			{
				...f.deps,
				httpClient: async () =>
					new Response(other, { headers: { "content-type": MediaType.EntityStatement } }),
			},
		);
		expect(discovery.ok).toBe(false);
		const wrongSubject = await signEntityStatement({ ...f.payload, sub: issuer }, f.signer, {
			typ: JwtTyp.EntityEventsStatement,
		});
		const result = await handler(
			{ entityId: issuer, subject, jwksFile: "keys.json" },
			{
				...f.deps,
				httpClient: async (url) =>
					String(url).includes("/.well-known/")
						? new Response(f.ec, { headers: { "content-type": MediaType.EntityStatement } })
						: new Response(wrongSubject, {
								headers: { "content-type": MediaType.EntityEventsStatement },
							}),
			},
		);
		expect(result.ok).toBe(false);
	});

	it("rejects missing or malformed pin files without network access", async () => {
		const f = await fixture();
		for (const content of ["not-json", "{}", '{"keys":[{}]}']) {
			f.deps.readFile.mockResolvedValue(content);
			expect((await handler({ entityId: issuer, subject, jwksFile: "keys.json" }, f.deps)).ok).toBe(
				false,
			);
		}
		f.deps.readFile.mockRejectedValue(new Error("missing"));
		expect(
			(await handler({ entityId: issuer, subject, jwksFile: "missing.json" }, f.deps)).ok,
		).toBe(false);
		expect(f.calls).toHaveLength(0);
	});

	it("registers real CLI arguments and supports authenticated POST input", async () => {
		const f = await fixture();
		f.deps.readFile.mockImplementation(async (path: string) =>
			path === "assertion.jwt" ? "signed.client.assertion\n" : JSON.stringify(f.jwks),
		);
		const program = new Command().exitOverride();
		register(program, f.deps);
		const output = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
		try {
			await program.parseAsync(
				[
					"subordinate-events",
					issuer,
					subject,
					"--jwks-file",
					"keys.json",
					"--client-assertion-file",
					"assertion.jwt",
				],
				{ from: "user" },
			);
			expect(output).toHaveBeenCalled();
			expect(f.calls[1]?.init?.method).toBe("POST");
			const body = new URLSearchParams(String(f.calls[1]?.init?.body));
			expect(body.get("sub")).toBe(subject);
			expect(body.get("client_assertion")).toBe("signed.client.assertion");
		} finally {
			output.mockRestore();
		}
		const missing = new Command().exitOverride().configureOutput({ writeErr: () => {} });
		register(missing, f.deps);
		await expect(
			missing.parseAsync(["subordinate-events", issuer, subject], { from: "user" }),
		).rejects.toThrow(/jwks-file/);
	});
});
