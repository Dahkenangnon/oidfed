import type { HttpClient } from "@oidfed/core";
import { Command } from "commander";
import { describe, expect, it, vi } from "vitest";
import { handler, register } from "../../src/commands/collection.js";
import { JsonFormatter } from "../../src/output/json.js";
import { createLogger } from "../../src/util/logger.js";

const endpoint = "https://independent.example/collect?version=1";
function fixture() {
	const calls: { url: URL; init: RequestInit | undefined }[] = [];
	const body = {
		entities: [{ entity_id: "https://leaf.example", extra: true }],
		next: "opaque",
		last_updated: -0.5,
	};
	const httpClient: HttpClient = async (url, init) => {
		calls.push({ url: new URL(String(url)), init });
		return new Response(JSON.stringify(body), { headers: { "content-type": "application/json" } });
	};
	return {
		calls,
		body,
		deps: {
			httpClient,
			formatter: new JsonFormatter(),
			logger: createLogger({ quiet: true, verbose: false }),
			readFile: vi.fn(async () => "assertion\n"),
		},
	};
}

describe("collection", () => {
	it("queries independent endpoints without Entity Configuration discovery", async () => {
		const f = fixture();
		const result = await handler(
			{
				endpoint,
				trustAnchor: "https://ta.example",
				entityType: ["one", "two"],
				trustMarkType: ["a", "b"],
				entityClaims: ["entity_infos", "entity_types"],
				infoClaims: ["display_name"],
				locale: ["en", "de"],
				from: "previous",
				limit: 2,
			},
			f.deps,
		);
		expect(result.ok).toBe(true);
		if (result.ok) expect(JSON.parse(result.value)).toEqual(f.body);
		expect(f.calls).toHaveLength(1);
		const params = f.calls[0]?.url.searchParams;
		expect(params.get("version")).toBe("1");
		expect(params.getAll("entity_type")).toEqual(["one", "two"]);
		expect(params.getAll("trust_mark_type")).toEqual(["a", "b"]);
		expect(params.getAll("locale")).toEqual(["en", "de"]);
		expect(params.get("from")).toBe("previous");
	});
	it("uses form POST and keeps assertions out of request URLs", async () => {
		const f = fixture();
		const result = await handler(
			{ endpoint, clientAssertionFile: "client.jwt", entityType: ["one", "two"] },
			f.deps,
		);
		expect(result.ok).toBe(true);
		expect(f.calls[0]?.init?.method).toBe("POST");
		expect(f.calls[0]?.init?.redirect).toBe("manual");
		expect(f.calls[0]?.url.searchParams.has("client_assertion")).toBe(false);
		expect(new URLSearchParams(String(f.calls[0]?.init?.body)).get("client_assertion")).toBe(
			"assertion",
		);
	});
	it("supports anonymous POST and propagates protocol failures", async () => {
		const f = fixture();
		expect((await handler({ endpoint, post: true }, f.deps)).ok).toBe(true);
		expect(f.calls[0]?.init?.method).toBe("POST");
		const result = await handler(
			{ endpoint },
			{
				...f.deps,
				httpClient: async () =>
					new Response(
						JSON.stringify({ error: "unsupported_claim", error_description: "Claim unavailable" }),
						{ status: 400, headers: { "content-type": "application/json" } },
					),
			},
		);
		expect(result).toEqual({
			ok: false,
			error: { code: "unsupported_claim", description: "Claim unavailable" },
		});
	});
	it("does not fetch when assertion input cannot be read or request values are invalid", async () => {
		const f = fixture();
		f.deps.readFile.mockRejectedValueOnce(new Error("missing"));
		expect((await handler({ endpoint, clientAssertionFile: "missing" }, f.deps)).ok).toBe(false);
		expect((await handler({ endpoint, limit: -1 }, f.deps)).ok).toBe(false);
		expect(f.calls).toHaveLength(0);
	});
	it.each(["-1", "1.5", "NaN", "9007199254740992"])(
		"reports invalid limit %s before making a request",
		async (value) => {
			const f = fixture();
			const stderr: string[] = [];
			const program = new Command()
				.exitOverride()
				.configureOutput({ writeErr: (text) => stderr.push(text) });
			register(program, f.deps);
			await expect(
				program.parseAsync(["collection", endpoint, "--limit", value], { from: "user" }),
			).rejects.toMatchObject({ code: "commander.invalidArgument" });
			expect(stderr.join("")).toContain("Expected a nonnegative safe integer");
			expect(f.calls).toHaveLength(0);
		},
	);
	it.each(["0", "9007199254740991"])("accepts valid limit %s", async (value) => {
		const f = fixture();
		const output = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
		try {
			const program = new Command().exitOverride();
			register(program, f.deps);
			await program.parseAsync(["collection", endpoint, "--limit", value], { from: "user" });
			expect(f.calls).toHaveLength(1);
			expect(f.calls[0]?.url.searchParams.get("limit")).toBe(value);
		} finally {
			output.mockRestore();
		}
	});

	it("preserves repeated command options and prints the informational response", async () => {
		const f = fixture();
		const output = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
		try {
			const program = new Command();
			register(program, f.deps);
			await program.parseAsync(
				[
					"collection",
					endpoint,
					"--entity-type",
					"one",
					"--entity-type",
					"two",
					"--locale",
					"en",
					"--locale",
					"de",
				],
				{ from: "user" },
			);
			expect(f.calls[0]?.url.searchParams.getAll("entity_type")).toEqual(["one", "two"]);
			expect(f.calls[0]?.url.searchParams.getAll("locale")).toEqual(["en", "de"]);
			expect(output).toHaveBeenCalledWith(`${JSON.stringify(f.body, null, 2)}\n`);
		} finally {
			output.mockRestore();
		}
	});
});
