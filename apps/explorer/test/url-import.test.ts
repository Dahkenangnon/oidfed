import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	diffAnchors,
	fetchSettings,
	mergeSettings,
	validateImportUrl,
} from "@/features/settings/lib/url-import";
import type { Settings } from "@/lib/settings";

const baseSettings: Settings = {
	trustAnchors: [],
	httpTimeoutMs: 10_000,
	maxChainDepth: 10,
	theme: "system",
	jsonIndent: 2,
	expirationWarningDays: [7, 30, 90],
};

describe("validateImportUrl", () => {
	it("accepts https URLs", () => {
		const r = validateImportUrl("https://example.com/settings.json");
		expect(r.ok).toBe(true);
	});

	it("accepts http URLs", () => {
		const r = validateImportUrl("http://example.com/settings.json");
		expect(r.ok).toBe(true);
	});

	it("rejects malformed URLs", () => {
		const r = validateImportUrl("not a url");
		expect(r.ok).toBe(false);
	});

	it("rejects non-http(s) schemes (data:, javascript:, file:)", () => {
		expect(validateImportUrl("data:application/json;base64,eyJ0cnVzdEFuY2hvcnMiOltdfQ==").ok).toBe(
			false,
		);
		expect(validateImportUrl("javascript:alert(1)").ok).toBe(false);
		expect(validateImportUrl("file:///etc/passwd").ok).toBe(false);
	});
});

describe("diffAnchors", () => {
	it("classifies each incoming anchor as new or already-present", () => {
		const current = [{ entityId: "https://ta1.example.com" }];
		const incoming = [
			{ entityId: "https://ta1.example.com" }, // duplicate
			{ entityId: "https://ta2.example.com" }, // new
			{ entityId: "https://ta3.example.com" }, // new
		];
		const diff = diffAnchors(current, incoming);
		expect(diff.alreadyPresent.map((a) => a.entityId)).toEqual(["https://ta1.example.com"]);
		expect(diff.toAdd.map((a) => a.entityId)).toEqual([
			"https://ta2.example.com",
			"https://ta3.example.com",
		]);
	});

	it("empty current → all incoming are new", () => {
		const diff = diffAnchors([], [{ entityId: "https://ta.example.com" }]);
		expect(diff.toAdd).toHaveLength(1);
		expect(diff.alreadyPresent).toHaveLength(0);
	});

	it("empty incoming → nothing to do", () => {
		const diff = diffAnchors([{ entityId: "https://ta.example.com" }], []);
		expect(diff.toAdd).toHaveLength(0);
		expect(diff.alreadyPresent).toHaveLength(0);
	});
});

describe("mergeSettings", () => {
	it("union of trust anchors, dedup by entityId, preserves order (existing first, new second)", () => {
		const current: Settings = {
			...baseSettings,
			trustAnchors: [{ entityId: "https://ta1.example.com" }],
		};
		const incoming: Settings = {
			...baseSettings,
			trustAnchors: [
				{ entityId: "https://ta1.example.com" },
				{ entityId: "https://ta2.example.com" },
			],
		};
		const merged = mergeSettings(current, incoming);
		expect(merged.trustAnchors.map((a) => a.entityId)).toEqual([
			"https://ta1.example.com",
			"https://ta2.example.com",
		]);
	});

	it("scalar fields stay on the current settings (NOT replaced by incoming)", () => {
		const current: Settings = {
			...baseSettings,
			httpTimeoutMs: 30_000,
			maxChainDepth: 25,
			theme: "dark",
		};
		const incoming: Settings = {
			...baseSettings,
			httpTimeoutMs: 1_000,
			maxChainDepth: 2,
			theme: "light",
		};
		const merged = mergeSettings(current, incoming);
		expect(merged.httpTimeoutMs).toBe(30_000);
		expect(merged.maxChainDepth).toBe(25);
		expect(merged.theme).toBe("dark");
	});

	it("identity case — merging the same settings yields no changes", () => {
		const merged = mergeSettings(baseSettings, baseSettings);
		expect(merged).toEqual(baseSettings);
	});
});

describe("fetchSettings", () => {
	let originalFetch: typeof globalThis.fetch;

	beforeEach(() => {
		originalFetch = globalThis.fetch;
	});
	afterEach(() => {
		globalThis.fetch = originalFetch;
		vi.restoreAllMocks();
	});

	it("returns invalid-url for a malformed URL without making a request", async () => {
		const spy = vi.fn();
		globalThis.fetch = spy as unknown as typeof globalThis.fetch;
		const r = await fetchSettings("not a url");
		expect(r.ok).toBe(false);
		if (!r.ok) expect(r.error.kind).toBe("invalid-url");
		expect(spy).not.toHaveBeenCalled();
	});

	it("returns invalid-url for non-http schemes without making a request", async () => {
		const spy = vi.fn();
		globalThis.fetch = spy as unknown as typeof globalThis.fetch;
		const r = await fetchSettings("file:///etc/passwd");
		expect(r.ok).toBe(false);
		if (!r.ok) expect(r.error.kind).toBe("invalid-url");
		expect(spy).not.toHaveBeenCalled();
	});

	it("returns network on a fetch rejection (CORS, DNS, etc.)", async () => {
		globalThis.fetch = vi.fn().mockRejectedValue(new TypeError("Failed to fetch"));
		const r = await fetchSettings("https://example.com/s.json");
		expect(r.ok).toBe(false);
		if (!r.ok) expect(r.error.kind).toBe("network");
	});

	it("returns http on a non-2xx response", async () => {
		globalThis.fetch = vi
			.fn()
			.mockResolvedValue(new Response("not found", { status: 404, statusText: "Not Found" }));
		const r = await fetchSettings("https://example.com/s.json");
		expect(r.ok).toBe(false);
		if (!r.ok && r.error.kind === "http") expect(r.error.status).toBe(404);
	});

	it("returns not-json when the body is not JSON", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue(
			new Response("<html>nope</html>", {
				status: 200,
				headers: { "content-type": "text/html" },
			}),
		);
		const r = await fetchSettings("https://example.com/s.json");
		expect(r.ok).toBe(false);
		if (!r.ok) expect(r.error.kind).toBe("not-json");
	});

	it("returns schema on a JSON body that doesn't match SettingsSchema", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue(
			new Response(JSON.stringify({ trustAnchors: [{ entityId: "not a url" }] }), {
				status: 200,
				headers: { "content-type": "application/json" },
			}),
		);
		const r = await fetchSettings("https://example.com/s.json");
		expect(r.ok).toBe(false);
		if (!r.ok) expect(r.error.kind).toBe("schema");
	});

	it("resolves to a validated Settings on a well-formed document", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue(
			new Response(
				JSON.stringify({
					trustAnchors: [{ entityId: "https://ta.example.com" }],
				}),
				{ status: 200, headers: { "content-type": "application/json" } },
			),
		);
		const r = await fetchSettings("https://example.com/s.json");
		expect(r.ok).toBe(true);
		if (r.ok) {
			expect(r.value.settings.trustAnchors).toHaveLength(1);
			expect(r.value.settings.trustAnchors[0]?.entityId).toBe("https://ta.example.com");
			expect(r.value.source).toBe("https://example.com/s.json");
		}
	});

	it("aborts when the caller's AbortSignal aborts", async () => {
		globalThis.fetch = vi.fn().mockImplementation(
			(_url, init?: RequestInit) =>
				new Promise((_resolve, reject) => {
					init?.signal?.addEventListener("abort", () =>
						reject(new DOMException("aborted", "AbortError")),
					);
				}),
		);
		const ctrl = new AbortController();
		const promise = fetchSettings("https://example.com/s.json", { signal: ctrl.signal });
		ctrl.abort();
		const r = await promise;
		expect(r.ok).toBe(false);
		if (!r.ok) expect(r.error.kind).toBe("network");
	});
});
