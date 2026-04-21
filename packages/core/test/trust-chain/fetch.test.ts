import { describe, expect, it, vi } from "vitest";
import { MemoryCache } from "../../src/cache/index.js";
import { isErr, isOk } from "../../src/errors.js";
import {
	expandIPv6,
	fetchEntityConfiguration,
	fetchSubordinateStatement,
	ipv4ToInt,
	isSpecialUseIP,
	isSpecialUseIPv4,
	isSpecialUseIPv6,
	validateEntityId,
	validateFetchUrl,
} from "../../src/trust-chain/fetch.js";
import type { EntityId } from "../../src/types.js";

describe("validateFetchUrl", () => {
	it("accepts valid HTTPS URL", () => {
		const result = validateFetchUrl("https://example.com/.well-known/openid-federation");
		expect(isOk(result)).toBe(true);
	});

	it("rejects non-HTTPS URL", () => {
		const result = validateFetchUrl("http://example.com/.well-known/openid-federation");
		expect(isErr(result)).toBe(true);
	});

	it("rejects URL with credentials", () => {
		const result = validateFetchUrl("https://user:pass@example.com/path");
		expect(isErr(result)).toBe(true);
	});

	it("rejects URL longer than 2048 characters", () => {
		const longUrl = `https://example.com/${"a".repeat(2048)}`;
		const result = validateFetchUrl(longUrl);
		expect(isErr(result)).toBe(true);
	});

	it("rejects invalid URL", () => {
		const result = validateFetchUrl("not-a-url");
		expect(isErr(result)).toBe(true);
	});

	it("rejects loopback IP 127.0.0.1", () => {
		const result = validateFetchUrl("https://127.0.0.1/.well-known/openid-federation");
		expect(isErr(result)).toBe(true);
	});

	it("rejects private IP 10.0.0.1", () => {
		const result = validateFetchUrl("https://10.0.0.1/.well-known/openid-federation");
		expect(isErr(result)).toBe(true);
	});

	it("rejects private IP 192.168.1.1", () => {
		const result = validateFetchUrl("https://192.168.1.1/.well-known/openid-federation");
		expect(isErr(result)).toBe(true);
	});

	it("rejects private IP 172.16.0.1", () => {
		const result = validateFetchUrl("https://172.16.0.1/.well-known/openid-federation");
		expect(isErr(result)).toBe(true);
	});

	it("allows public IP", () => {
		const result = validateFetchUrl("https://8.8.8.8/.well-known/openid-federation");
		expect(isOk(result)).toBe(true);
	});

	it("respects allowedHosts filter", () => {
		const result = validateFetchUrl("https://allowed.example.com/path", {
			allowedHosts: ["allowed.example.com"],
		});
		expect(isOk(result)).toBe(true);

		const blocked = validateFetchUrl("https://other.example.com/path", {
			allowedHosts: ["allowed.example.com"],
		});
		expect(isErr(blocked)).toBe(true);
	});
});

describe("validateEntityId", () => {
	it("accepts valid entity ID", () => {
		const result = validateEntityId("https://example.com");
		expect(isOk(result)).toBe(true);
	});

	it("rejects non-HTTPS entity ID", () => {
		const result = validateEntityId("http://example.com");
		expect(isErr(result)).toBe(true);
	});

	it("rejects entity ID with credentials", () => {
		const result = validateEntityId("https://user:pass@example.com");
		expect(isErr(result)).toBe(true);
	});
});

describe("fetchEntityConfiguration", () => {
	it("constructs correct URL with /.well-known/openid-federation", async () => {
		let capturedUrl = "";
		const mockFetch = vi.fn(async (url: string | URL | Request) => {
			capturedUrl = url.toString();
			return new Response("jwt-token", {
				status: 200,
				headers: { "Content-Type": "application/entity-statement+jwt" },
			});
		});

		const result = await fetchEntityConfiguration("https://example.com" as EntityId, {
			httpClient: mockFetch,
		});
		expect(isOk(result)).toBe(true);
		expect(capturedUrl).toBe("https://example.com/.well-known/openid-federation");
	});

	it("strips trailing slash from entity ID before constructing well-known URL", async () => {
		let capturedUrl = "";
		const mockFetch = vi.fn(async (url: string | URL | Request) => {
			capturedUrl = url.toString();
			return new Response("jwt-token", {
				status: 200,
				headers: { "Content-Type": "application/entity-statement+jwt" },
			});
		});

		const result = await fetchEntityConfiguration("https://example.com/" as EntityId, {
			httpClient: mockFetch,
		});
		expect(isOk(result)).toBe(true);
		expect(capturedUrl).toBe("https://example.com/.well-known/openid-federation");
	});

	it("sets Accept header for entity-statement+jwt", async () => {
		let capturedInit: RequestInit | undefined;
		const mockFetch = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
			capturedInit = init;
			return new Response("jwt", {
				status: 200,
				headers: { "Content-Type": "application/entity-statement+jwt" },
			});
		});

		await fetchEntityConfiguration("https://example.com" as EntityId, {
			httpClient: mockFetch,
		});
		expect(capturedInit?.headers).toBeDefined();
		const headers = new Headers(capturedInit?.headers);
		expect(headers.get("Accept")).toBe("application/entity-statement+jwt");
	});

	it("returns cached result on cache hit", async () => {
		const cache = new MemoryCache();
		const mockFetch = vi.fn(
			async () =>
				new Response("jwt", {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				}),
		);

		// First call: cache miss, fetches
		const r1 = await fetchEntityConfiguration("https://example.com" as EntityId, {
			httpClient: mockFetch,
			cache,
		});
		expect(isOk(r1)).toBe(true);
		expect(mockFetch).toHaveBeenCalledTimes(1);

		// Second call: cache hit, no fetch
		const r2 = await fetchEntityConfiguration("https://example.com" as EntityId, {
			httpClient: mockFetch,
			cache,
		});
		expect(isOk(r2)).toBe(true);
		expect(mockFetch).toHaveBeenCalledTimes(1);
	});

	it("returns error on non-200 status", async () => {
		const mockFetch = vi.fn(async () => new Response("Not found", { status: 404 }));

		const result = await fetchEntityConfiguration("https://example.com" as EntityId, {
			httpClient: mockFetch,
		});
		expect(isErr(result)).toBe(true);
		if (isErr(result)) {
			expect(result.error.code).toBe("ERR_NETWORK");
		}
	});

	it("rejects response with wrong Content-Type", async () => {
		const mockFetch = vi.fn(
			async () =>
				new Response("not-a-jwt", {
					status: 200,
					headers: { "Content-Type": "text/html" },
				}),
		);

		const result = await fetchEntityConfiguration("https://example.com" as EntityId, {
			httpClient: mockFetch,
		});
		expect(isErr(result)).toBe(true);
		if (isErr(result)) {
			expect(result.error.code).toBe("ERR_NETWORK");
			expect(result.error.description).toContain("Content-Type");
		}
	});

	it("accepts response with Content-Type including charset parameter", async () => {
		const mockFetch = vi.fn(
			async () =>
				new Response("jwt-token", {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt; charset=utf-8" },
				}),
		);

		const result = await fetchEntityConfiguration("https://example.com" as EntityId, {
			httpClient: mockFetch,
		});
		expect(isOk(result)).toBe(true);
	});

	it("rejects response with default text/plain Content-Type", async () => {
		// When no explicit Content-Type is set, Response defaults to text/plain
		const mockFetch = vi.fn(
			async () =>
				new Response("jwt-token", {
					status: 200,
				}),
		);

		const result = await fetchEntityConfiguration("https://example.com" as EntityId, {
			httpClient: mockFetch,
		});
		expect(isErr(result)).toBe(true);
		if (isErr(result)) {
			expect(result.error.code).toBe("ERR_NETWORK");
			expect(result.error.description).toContain("Content-Type");
		}
	});

	it("rejects response exceeding maxResponseBytes via Content-Length", async () => {
		const mockFetch = vi.fn(
			async () =>
				new Response("small body", {
					status: 200,
					headers: {
						"Content-Type": "application/entity-statement+jwt",
						"Content-Length": "999999",
					},
				}),
		);

		const result = await fetchEntityConfiguration("https://example.com" as EntityId, {
			httpClient: mockFetch,
			maxResponseBytes: 1024,
		});
		expect(isErr(result)).toBe(true);
		if (isErr(result)) {
			expect(result.error.description).toContain("Response too large");
		}
	});

	it("rejects response exceeding maxResponseBytes via body length", async () => {
		const largeBody = "x".repeat(2048);
		const mockFetch = vi.fn(
			async () =>
				new Response(largeBody, {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				}),
		);

		const result = await fetchEntityConfiguration("https://example.com" as EntityId, {
			httpClient: mockFetch,
			maxResponseBytes: 1024,
		});
		expect(isErr(result)).toBe(true);
		if (isErr(result)) {
			expect(result.error.description).toContain("Response too large");
		}
	});

	it("accepts response body exactly at limit", async () => {
		const limit = 1024;
		const body = "x".repeat(limit);
		const mockFetch = vi.fn(
			async () =>
				new Response(body, {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				}),
		);

		const result = await fetchEntityConfiguration("https://example.com" as EntityId, {
			httpClient: mockFetch,
			maxResponseBytes: limit,
		});
		expect(isOk(result)).toBe(true);
	});

	it("rejects response body 1 byte over limit when streamed", async () => {
		const limit = 1024;
		const body = "x".repeat(limit + 1);
		const encoder = new TextEncoder();
		const encoded = encoder.encode(body);
		const stream = new ReadableStream<Uint8Array>({
			start(controller) {
				controller.enqueue(encoded);
				controller.close();
			},
		});
		const mockFetch = vi.fn(
			async () =>
				new Response(stream, {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				}),
		);

		const result = await fetchEntityConfiguration("https://example.com" as EntityId, {
			httpClient: mockFetch,
			maxResponseBytes: limit,
		});
		expect(isErr(result)).toBe(true);
		if (isErr(result)) {
			expect(result.error.description).toContain("Response too large");
		}
	});

	it("rejects spoofed Content-Length with oversized streaming body", async () => {
		const limit = 1024;
		const body = "x".repeat(limit + 100);
		const encoder = new TextEncoder();
		const encoded = encoder.encode(body);
		const stream = new ReadableStream<Uint8Array>({
			start(controller) {
				controller.enqueue(encoded);
				controller.close();
			},
		});
		const mockFetch = vi.fn(
			async () =>
				new Response(stream, {
					status: 200,
					headers: {
						"Content-Type": "application/entity-statement+jwt",
						"Content-Length": "10", // spoofed small value
					},
				}),
		);

		const result = await fetchEntityConfiguration("https://example.com" as EntityId, {
			httpClient: mockFetch,
			maxResponseBytes: limit,
		});
		expect(isErr(result)).toBe(true);
		if (isErr(result)) {
			expect(result.error.description).toContain("Response too large");
		}
	});

	it("returns timeout error on abort", async () => {
		const mockFetch = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
			// Simulate abort
			return new Promise<Response>((_, reject) => {
				if (init?.signal) {
					init.signal.addEventListener("abort", () => {
						const abortError = new DOMException("Aborted", "AbortError");
						reject(abortError);
					});
				}
			});
		});

		const controller = new AbortController();
		const promise = fetchEntityConfiguration("https://example.com" as EntityId, {
			httpClient: mockFetch,
			signal: controller.signal,
			httpTimeoutMs: 60000,
		});
		// Abort immediately
		controller.abort();
		const result = await promise;
		expect(isErr(result)).toBe(true);
		if (isErr(result)) {
			expect(result.error.code).toBe("ERR_TIMEOUT");
		}
	});
});

describe("fetchEntityConfiguration — SSRF protection", () => {
	it("rejects HTTP (non-HTTPS) entity ID", async () => {
		const mockFetch = vi.fn();
		const result = await fetchEntityConfiguration("http://example.com" as EntityId, {
			httpClient: mockFetch,
		});
		expect(isErr(result)).toBe(true);
		if (isErr(result)) {
			expect(result.error.description).toContain("HTTPS");
		}
		expect(mockFetch).not.toHaveBeenCalled();
	});

	it("rejects private IP 127.0.0.1", async () => {
		const mockFetch = vi.fn();
		const result = await fetchEntityConfiguration("https://127.0.0.1" as EntityId, {
			httpClient: mockFetch,
		});
		expect(isErr(result)).toBe(true);
		if (isErr(result)) {
			expect(result.error.description).toContain("special-use address");
		}
		expect(mockFetch).not.toHaveBeenCalled();
	});

	it("rejects private IP 10.0.0.1", async () => {
		const mockFetch = vi.fn();
		const result = await fetchEntityConfiguration("https://10.0.0.1" as EntityId, {
			httpClient: mockFetch,
		});
		expect(isErr(result)).toBe(true);
		expect(mockFetch).not.toHaveBeenCalled();
	});

	it("rejects private IP 172.16.0.1", async () => {
		const mockFetch = vi.fn();
		const result = await fetchEntityConfiguration("https://172.16.0.1" as EntityId, {
			httpClient: mockFetch,
		});
		expect(isErr(result)).toBe(true);
		expect(mockFetch).not.toHaveBeenCalled();
	});

	it("rejects private IP 192.168.1.1", async () => {
		const mockFetch = vi.fn();
		const result = await fetchEntityConfiguration("https://192.168.1.1" as EntityId, {
			httpClient: mockFetch,
		});
		expect(isErr(result)).toBe(true);
		expect(mockFetch).not.toHaveBeenCalled();
	});

	it("rejects URL with credentials", async () => {
		const mockFetch = vi.fn();
		const result = await fetchEntityConfiguration("https://user:pass@example.com" as EntityId, {
			httpClient: mockFetch,
		});
		expect(isErr(result)).toBe(true);
		if (isErr(result)) {
			expect(result.error.description).toContain("credentials");
		}
		expect(mockFetch).not.toHaveBeenCalled();
	});

	it("rejects URL exceeding 2048 characters", async () => {
		const mockFetch = vi.fn();
		const longId = `https://example.com/${"a".repeat(2048)}` as EntityId;
		const result = await fetchEntityConfiguration(longId, {
			httpClient: mockFetch,
		});
		expect(isErr(result)).toBe(true);
		if (isErr(result)) {
			expect(result.error.description).toContain("2048");
		}
		expect(mockFetch).not.toHaveBeenCalled();
	});
});

describe("fetchSubordinateStatement — SSRF protection", () => {
	it("rejects HTTP fetch endpoint", async () => {
		const mockFetch = vi.fn();
		const result = await fetchSubordinateStatement(
			"http://example.com/federation_fetch",
			"https://sub.example.com" as EntityId,
			{ httpClient: mockFetch },
		);
		expect(isErr(result)).toBe(true);
		expect(mockFetch).not.toHaveBeenCalled();
	});

	it("rejects private IP fetch endpoint", async () => {
		const mockFetch = vi.fn();
		const result = await fetchSubordinateStatement(
			"https://192.168.1.1/federation_fetch",
			"https://sub.example.com" as EntityId,
			{ httpClient: mockFetch },
		);
		expect(isErr(result)).toBe(true);
		expect(mockFetch).not.toHaveBeenCalled();
	});
});

describe("fetchSubordinateStatement", () => {
	it("constructs URL with ?sub= query parameter", async () => {
		let capturedUrl = "";
		const mockFetch = vi.fn(async (url: string | URL | Request) => {
			capturedUrl = url.toString();
			return new Response("jwt", {
				status: 200,
				headers: { "Content-Type": "application/entity-statement+jwt" },
			});
		});

		const result = await fetchSubordinateStatement(
			"https://superior.example.com/federation_fetch",
			"https://subject.example.com" as EntityId,
			{ httpClient: mockFetch },
		);
		expect(isOk(result)).toBe(true);
		expect(capturedUrl).toContain("sub=https%3A%2F%2Fsubject.example.com");
	});

	it("returns error for non-200 response", async () => {
		const mockFetch = vi.fn(async () => new Response("Error", { status: 500 }));

		const result = await fetchSubordinateStatement(
			"https://superior.example.com/federation_fetch",
			"https://subject.example.com" as EntityId,
			{ httpClient: mockFetch },
		);
		expect(isErr(result)).toBe(true);
	});
});

// ---------------------------------------------------------------------------
// IANA Special-Use IP detection — exhaustive coverage per IANA registries
// ---------------------------------------------------------------------------

describe("ipv4ToInt", () => {
	it("converts valid IPv4 addresses", () => {
		expect(ipv4ToInt("0.0.0.0")).toBe(0x00000000);
		expect(ipv4ToInt("127.0.0.1")).toBe(0x7f000001);
		expect(ipv4ToInt("10.0.0.1")).toBe(0x0a000001);
		expect(ipv4ToInt("255.255.255.255")).toBe(0xffffffff);
		expect(ipv4ToInt("8.8.8.8")).toBe(0x08080808);
	});

	it("returns -1 for non-IPv4 strings", () => {
		expect(ipv4ToInt("not-an-ip")).toBe(-1);
		expect(ipv4ToInt("::1")).toBe(-1);
		expect(ipv4ToInt("256.0.0.1")).toBe(-1);
		expect(ipv4ToInt("1.2.3")).toBe(-1);
	});
});

describe("isSpecialUseIPv4", () => {
	it("blocks 0.0.0.0/8 — This network", () => {
		expect(isSpecialUseIPv4("0.0.0.0")).toBe(true);
		expect(isSpecialUseIPv4("0.1.2.3")).toBe(true);
		expect(isSpecialUseIPv4("0.255.255.255")).toBe(true);
	});

	it("blocks 10.0.0.0/8 — Private", () => {
		expect(isSpecialUseIPv4("10.0.0.0")).toBe(true);
		expect(isSpecialUseIPv4("10.0.0.1")).toBe(true);
		expect(isSpecialUseIPv4("10.255.255.255")).toBe(true);
	});

	it("blocks 100.64.0.0/10 — Shared Address Space", () => {
		expect(isSpecialUseIPv4("100.64.0.0")).toBe(true);
		expect(isSpecialUseIPv4("100.64.0.1")).toBe(true);
		expect(isSpecialUseIPv4("100.127.255.255")).toBe(true);
		expect(isSpecialUseIPv4("100.63.255.255")).toBe(false); // just outside
		expect(isSpecialUseIPv4("100.128.0.0")).toBe(false); // just outside
	});

	it("blocks 127.0.0.0/8 — Loopback", () => {
		expect(isSpecialUseIPv4("127.0.0.1")).toBe(true);
		expect(isSpecialUseIPv4("127.255.255.255")).toBe(true);
	});

	it("blocks 169.254.0.0/16 — Link-local", () => {
		expect(isSpecialUseIPv4("169.254.0.0")).toBe(true);
		expect(isSpecialUseIPv4("169.254.1.1")).toBe(true);
		expect(isSpecialUseIPv4("169.254.255.255")).toBe(true);
	});

	it("blocks 172.16.0.0/12 — Private", () => {
		expect(isSpecialUseIPv4("172.16.0.0")).toBe(true);
		expect(isSpecialUseIPv4("172.16.0.1")).toBe(true);
		expect(isSpecialUseIPv4("172.31.255.255")).toBe(true);
		expect(isSpecialUseIPv4("172.15.255.255")).toBe(false); // just outside
		expect(isSpecialUseIPv4("172.32.0.0")).toBe(false); // just outside
	});

	it("blocks 192.0.0.0/24 — IETF Protocol Assignments", () => {
		expect(isSpecialUseIPv4("192.0.0.0")).toBe(true);
		expect(isSpecialUseIPv4("192.0.0.255")).toBe(true);
	});

	it("blocks 192.0.2.0/24 — TEST-NET-1 (documentation)", () => {
		expect(isSpecialUseIPv4("192.0.2.0")).toBe(true);
		expect(isSpecialUseIPv4("192.0.2.1")).toBe(true);
		expect(isSpecialUseIPv4("192.0.2.255")).toBe(true);
	});

	it("blocks 192.88.99.0/24 — 6to4 Relay Anycast", () => {
		expect(isSpecialUseIPv4("192.88.99.0")).toBe(true);
		expect(isSpecialUseIPv4("192.88.99.255")).toBe(true);
	});

	it("blocks 192.168.0.0/16 — Private", () => {
		expect(isSpecialUseIPv4("192.168.0.0")).toBe(true);
		expect(isSpecialUseIPv4("192.168.1.1")).toBe(true);
		expect(isSpecialUseIPv4("192.168.255.255")).toBe(true);
	});

	it("blocks 198.18.0.0/15 — Benchmarking", () => {
		expect(isSpecialUseIPv4("198.18.0.0")).toBe(true);
		expect(isSpecialUseIPv4("198.19.255.255")).toBe(true);
		expect(isSpecialUseIPv4("198.17.255.255")).toBe(false); // just outside
		expect(isSpecialUseIPv4("198.20.0.0")).toBe(false); // just outside
	});

	it("blocks 198.51.100.0/24 — TEST-NET-2 (documentation)", () => {
		expect(isSpecialUseIPv4("198.51.100.0")).toBe(true);
		expect(isSpecialUseIPv4("198.51.100.255")).toBe(true);
	});

	it("blocks 203.0.113.0/24 — TEST-NET-3 (documentation)", () => {
		expect(isSpecialUseIPv4("203.0.113.0")).toBe(true);
		expect(isSpecialUseIPv4("203.0.113.255")).toBe(true);
	});

	it("blocks 224.0.0.0/4 — Multicast", () => {
		expect(isSpecialUseIPv4("224.0.0.0")).toBe(true);
		expect(isSpecialUseIPv4("239.255.255.255")).toBe(true);
	});

	it("blocks 240.0.0.0/4 — Reserved", () => {
		expect(isSpecialUseIPv4("240.0.0.0")).toBe(true);
		expect(isSpecialUseIPv4("254.255.255.255")).toBe(true);
	});

	it("blocks 255.255.255.255/32 — Limited Broadcast", () => {
		expect(isSpecialUseIPv4("255.255.255.255")).toBe(true);
	});

	it("allows public unicast addresses", () => {
		expect(isSpecialUseIPv4("8.8.8.8")).toBe(false);
		expect(isSpecialUseIPv4("1.1.1.1")).toBe(false);
		expect(isSpecialUseIPv4("93.184.216.34")).toBe(false); // example.com
		expect(isSpecialUseIPv4("208.67.222.222")).toBe(false);
	});
});

describe("expandIPv6", () => {
	it("expands :: (all zeros)", () => {
		expect(expandIPv6("::")).toBe("00000000000000000000000000000000");
	});

	it("expands ::1 (loopback)", () => {
		expect(expandIPv6("::1")).toBe("00000000000000000000000000000001");
	});

	it("expands full address without ::", () => {
		expect(expandIPv6("2001:0db8:0000:0000:0000:0000:0000:0001")).toBe(
			"20010db8000000000000000000000001",
		);
	});

	it("expands address with :: in the middle", () => {
		expect(expandIPv6("fe80::1")).toBe("fe800000000000000000000000000001");
	});

	it("handles IPv4-mapped notation ::ffff:192.168.1.1", () => {
		expect(expandIPv6("::ffff:192.168.1.1")).toBe("00000000000000000000ffffc0a80101");
	});

	it("returns empty string for invalid addresses", () => {
		expect(expandIPv6("not-an-ipv6")).toBe("");
		expect(expandIPv6("::1::2")).toBe(""); // two :: separators
	});
});

describe("isSpecialUseIPv6", () => {
	it("blocks :: — Unspecified Address", () => {
		expect(isSpecialUseIPv6("::")).toBe(true);
	});

	it("blocks ::1 — Loopback", () => {
		expect(isSpecialUseIPv6("::1")).toBe(true);
	});

	it("blocks ::ffff:0:0/96 — IPv4-mapped (any IPv4)", () => {
		expect(isSpecialUseIPv6("::ffff:192.168.1.1")).toBe(true);
		expect(isSpecialUseIPv6("::ffff:10.0.0.1")).toBe(true);
		expect(isSpecialUseIPv6("::ffff:8.8.8.8")).toBe(true);
	});

	it("blocks 64:ff9b::/96 — IPv4/IPv6 translation", () => {
		expect(isSpecialUseIPv6("64:ff9b::1")).toBe(true);
		expect(isSpecialUseIPv6("64:ff9b::192.0.2.1")).toBe(true);
	});

	it("blocks 64:ff9b:1::/48 — IPv4/IPv6 translation", () => {
		expect(isSpecialUseIPv6("64:ff9b:1::")).toBe(true);
		expect(isSpecialUseIPv6("64:ff9b:1:0:0:0:0:1")).toBe(true);
	});

	it("blocks 100::/64 — Discard-only", () => {
		expect(isSpecialUseIPv6("100::1")).toBe(true);
		expect(isSpecialUseIPv6("100:0:0:0::1")).toBe(true); // still inside /64
		expect(isSpecialUseIPv6("100:1::")).toBe(false); // outside /64 (second group ≠ 0)
	});

	it("blocks 2001::/23 — IETF Protocol Assignments (second group 0000–01ff)", () => {
		expect(isSpecialUseIPv6("2001::1")).toBe(true); // 2001:0000:: — Teredo
		expect(isSpecialUseIPv6("2001:1::")).toBe(true); // 2001:0001:: — inside /23
		expect(isSpecialUseIPv6("2001:1ff::")).toBe(true); // 2001:01ff:: — boundary
		expect(isSpecialUseIPv6("2001:200::")).toBe(false); // 2001:0200:: — outside /23
	});

	it("blocks 2001:db8::/32 — Documentation (separate entry)", () => {
		expect(isSpecialUseIPv6("2001:db8::1")).toBe(true);
		expect(isSpecialUseIPv6("2001:db8:85a3::8a2e:370:7334")).toBe(true);
	});

	it("blocks 2002::/16 — 6to4", () => {
		expect(isSpecialUseIPv6("2002::1")).toBe(true);
		expect(isSpecialUseIPv6("2002:c000:204::")).toBe(true);
	});

	it("blocks fc00::/7 — Unique-Local (fc::/8 and fd::/8)", () => {
		expect(isSpecialUseIPv6("fc00::1")).toBe(true);
		expect(isSpecialUseIPv6("fd00::1")).toBe(true);
		expect(isSpecialUseIPv6("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")).toBe(true);
		expect(isSpecialUseIPv6("fe00::1")).toBe(false); // outside fc00::/7
	});

	it("blocks fe80::/10 — Link-local Unicast", () => {
		expect(isSpecialUseIPv6("fe80::1")).toBe(true);
		expect(isSpecialUseIPv6("fe80::dead:beef")).toBe(true);
		expect(isSpecialUseIPv6("fe8f::1")).toBe(true);
		expect(isSpecialUseIPv6("fe90::1")).toBe(true);
		expect(isSpecialUseIPv6("fea0::1")).toBe(true);
		expect(isSpecialUseIPv6("feb0::1")).toBe(true);
		expect(isSpecialUseIPv6("febf::1")).toBe(true);
		expect(isSpecialUseIPv6("fec0::1")).toBe(false); // outside fe80::/10
	});

	it("blocks ff00::/8 — Multicast", () => {
		expect(isSpecialUseIPv6("ff02::1")).toBe(true); // all-nodes multicast
		expect(isSpecialUseIPv6("ff02::2")).toBe(true); // all-routers multicast
		expect(isSpecialUseIPv6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")).toBe(true);
	});

	it("allows public global unicast addresses", () => {
		expect(isSpecialUseIPv6("2607:f8b0:4004:800::200e")).toBe(false); // Google IPv6
		expect(isSpecialUseIPv6("2a00:1450:4001:81e::200e")).toBe(false); // Google EU
		expect(isSpecialUseIPv6("2606:4700:4700::1111")).toBe(false); // Cloudflare
		expect(isSpecialUseIPv6("2001:4860:4860::8888")).toBe(false); // Google DNS (outside 2001::/23)
	});
});

describe("isSpecialUseIP", () => {
	it("dispatches to isSpecialUseIPv4 for IPv4 addresses", () => {
		expect(isSpecialUseIP("10.0.0.1")).toBe(true);
		expect(isSpecialUseIP("8.8.8.8")).toBe(false);
	});

	it("dispatches to isSpecialUseIPv6 for bare IPv6 addresses", () => {
		expect(isSpecialUseIP("::1")).toBe(true);
		expect(isSpecialUseIP("2607:f8b0:4004:800::200e")).toBe(false);
	});

	it("handles bracketed IPv6 literals from URL hostnames", () => {
		expect(isSpecialUseIP("[::1]")).toBe(true);
		expect(isSpecialUseIP("[fe80::1]")).toBe(true);
		expect(isSpecialUseIP("[fc00::1]")).toBe(true);
		expect(isSpecialUseIP("[2607:f8b0:4004:800::200e]")).toBe(false);
	});
});

describe("validateFetchUrl — IANA special-use IP blocking", () => {
	it("rejects IPv6 loopback literal [::1]", () => {
		const result = validateFetchUrl("https://[::1]/.well-known/openid-federation");
		expect(isErr(result)).toBe(true);
		if (isErr(result)) {
			expect(result.error.description).toContain("special-use address");
		}
	});

	it("rejects IPv6 link-local literal [fe80::1]", () => {
		const result = validateFetchUrl("https://[fe80::1]/.well-known/openid-federation");
		expect(isErr(result)).toBe(true);
		if (isErr(result)) {
			expect(result.error.description).toContain("special-use address");
		}
	});

	it("rejects IPv6 ULA literal [fc00::1]", () => {
		const result = validateFetchUrl("https://[fc00::1]/.well-known/openid-federation");
		expect(isErr(result)).toBe(true);
	});

	it("rejects documentation address [2001:db8::1]", () => {
		const result = validateFetchUrl("https://[2001:db8::1]/.well-known/openid-federation");
		expect(isErr(result)).toBe(true);
	});

	it("rejects IANA ranges not in old DEFAULT_BLOCKED_CIDRS — 100.64.0.1 (shared space)", () => {
		const result = validateFetchUrl("https://100.64.0.1/.well-known/openid-federation");
		expect(isErr(result)).toBe(true);
		if (isErr(result)) {
			expect(result.error.description).toContain("special-use address");
		}
	});

	it("rejects 192.0.2.1 (TEST-NET-1, not in old blocklist)", () => {
		const result = validateFetchUrl("https://192.0.2.1/.well-known/openid-federation");
		expect(isErr(result)).toBe(true);
	});

	it("accepts public IPv6 address", () => {
		const result = validateFetchUrl(
			"https://[2607:f8b0:4004:800::200e]/.well-known/openid-federation",
		);
		expect(isOk(result)).toBe(true);
	});

	it("user-supplied blockedCIDRs are additive and still reported as blocked CIDR range", () => {
		const result = validateFetchUrl("https://203.0.114.1/.well-known/openid-federation", {
			blockedCIDRs: ["203.0.114.0/24"],
		});
		expect(isErr(result)).toBe(true);
		if (isErr(result)) {
			expect(result.error.description).toContain("blocked CIDR range");
		}
	});
});
