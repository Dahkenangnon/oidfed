import { describe, expect, it } from "vitest";
import {
	errorResponse,
	extractRequestParams,
	jsonResponse,
	jwtResponse,
	parseQueryParams,
	readBodyWithLimit,
	readStreamWithLimit,
	requireMethod,
	requireMethods,
	SECURITY_HEADERS,
	toPublicError,
} from "../src/http.js";

describe("SECURITY_HEADERS", () => {
	it("contains all 5 expected security headers", () => {
		expect(SECURITY_HEADERS["Cache-Control"]).toBe("no-store");
		expect(SECURITY_HEADERS["X-Content-Type-Options"]).toBe("nosniff");
		expect(SECURITY_HEADERS["Strict-Transport-Security"]).toBe(
			"max-age=31536000; includeSubDomains",
		);
		expect(SECURITY_HEADERS["X-Frame-Options"]).toBe("DENY");
		expect(SECURITY_HEADERS["Referrer-Policy"]).toBe("no-referrer");
		expect(Object.keys(SECURITY_HEADERS)).toHaveLength(5);
	});
});

describe("jwtResponse", () => {
	it("returns 200 with correct Content-Type and security headers", () => {
		const res = jwtResponse("eyJhbGc...", "application/entity-statement+jwt");
		expect(res.status).toBe(200);
		expect(res.headers.get("Content-Type")).toBe("application/entity-statement+jwt");
		expect(res.headers.get("Cache-Control")).toBe("no-store");
		expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
	});
});

describe("jsonResponse", () => {
	it("returns 200 with JSON Content-Type by default", async () => {
		const res = jsonResponse({ foo: "bar" });
		expect(res.status).toBe(200);
		expect(res.headers.get("Content-Type")).toBe("application/json");
		const body = await res.json();
		expect(body).toEqual({ foo: "bar" });
	});

	it("accepts a custom status code", () => {
		const res = jsonResponse({ ok: true }, 201);
		expect(res.status).toBe(201);
	});
});

describe("errorResponse", () => {
	it("returns OAuth-style error with security headers", async () => {
		const res = errorResponse(400, "invalid_request", "bad param");
		expect(res.status).toBe(400);
		expect(res.headers.get("Content-Type")).toBe("application/json");
		expect(res.headers.get("Cache-Control")).toBe("no-store");
		const body = await res.json();
		expect(body).toEqual({ error: "invalid_request", error_description: "bad param" });
	});
});

describe("toPublicError", () => {
	it("passes through known federation error codes", () => {
		const result = toPublicError({ code: "invalid_request", description: "bad param" });
		expect(result.code).toBe("invalid_request");
		expect(result.description).toBe("bad param");
		expect(result.status).toBe(400);
	});

	it("sanitizes internal error codes to server_error", () => {
		const result = toPublicError({
			code: "ERR_SIGNATURE_INVALID",
			description: "secret internal detail",
		});
		expect(result.code).toBe("server_error");
		expect(result.description).toBe("An internal error occurred");
		expect(result.status).toBe(500);
	});

	it("maps invalid_client to 401", () => {
		const result = toPublicError({ code: "invalid_client", description: "bad client" });
		expect(result.status).toBe(401);
	});

	it("maps not_found to 404", () => {
		const result = toPublicError({ code: "not_found", description: "gone" });
		expect(result.status).toBe(404);
	});

	it("maps temporarily_unavailable to 503", () => {
		const result = toPublicError({
			code: "temporarily_unavailable",
			description: "try later",
		});
		expect(result.status).toBe(503);
	});
});

describe("requireMethod", () => {
	it("returns null when method matches", () => {
		const req = new Request("https://example.com", { method: "GET" });
		expect(requireMethod(req, "GET")).toBeNull();
	});

	it("returns 405 with Allow header when method mismatches", async () => {
		const req = new Request("https://example.com", { method: "POST" });
		const res = requireMethod(req, "GET");
		expect(res).not.toBeNull();
		expect(res?.status).toBe(405);
		expect(res?.headers.get("Allow")).toBe("GET");
	});
});

describe("requireMethods", () => {
	it("returns null when method is in allowed list", () => {
		const req = new Request("https://example.com", { method: "POST" });
		expect(requireMethods(req, ["GET", "POST"])).toBeNull();
	});

	it("returns 405 with joined Allow header", () => {
		const req = new Request("https://example.com", { method: "DELETE" });
		const res = requireMethods(req, ["GET", "POST"]);
		expect(res).not.toBeNull();
		expect(res?.status).toBe(405);
		expect(res?.headers.get("Allow")).toBe("GET, POST");
	});
});

describe("parseQueryParams", () => {
	it("extracts params from URL", () => {
		const req = new Request("https://example.com/path?foo=bar&baz=42");
		const params = parseQueryParams(req);
		expect(params.get("foo")).toBe("bar");
		expect(params.get("baz")).toBe("42");
	});
});

describe("extractRequestParams", () => {
	it("extracts query params for GET", async () => {
		const req = new Request("https://example.com?sub=https://leaf.example.com");
		const result = await extractRequestParams(req);
		expect(result.params.get("sub")).toBe("https://leaf.example.com");
		expect(result.clientAssertion).toBeUndefined();
	});

	it("extracts body params and client_assertion for POST", async () => {
		const body =
			"grant_type=client_credentials&client_assertion=jwt123&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer";
		const req = new Request("https://example.com", {
			method: "POST",
			body,
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
		});
		const result = await extractRequestParams(req);
		expect(result.clientAssertion).toBe("jwt123");
		expect(result.clientAssertionType).toBe(
			"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		);
		expect(result.params.get("grant_type")).toBe("client_credentials");
		// client_assertion should be removed from params
		expect(result.params.get("client_assertion")).toBeNull();
	});
});

describe("readStreamWithLimit", () => {
	it("reads stream within limit", async () => {
		const stream = new ReadableStream({
			start(controller) {
				controller.enqueue(new TextEncoder().encode("hello"));
				controller.close();
			},
		});
		const result = await readStreamWithLimit(stream, 100);
		expect(result).toEqual({ ok: true, text: "hello" });
	});

	it("rejects stream exceeding limit", async () => {
		const stream = new ReadableStream({
			start(controller) {
				controller.enqueue(new TextEncoder().encode("x".repeat(200)));
				controller.close();
			},
		});
		const result = await readStreamWithLimit(stream, 100);
		expect(result).toEqual({ ok: false });
	});
});

describe("readBodyWithLimit", () => {
	it("returns ok: false for null body", async () => {
		const req = new Request("https://example.com");
		const result = await readBodyWithLimit(req, 1024);
		expect(result).toEqual({ ok: false });
	});

	it("reads body within limit", async () => {
		const req = new Request("https://example.com", {
			method: "POST",
			body: "small body",
		});
		const result = await readBodyWithLimit(req, 1024);
		expect(result).toEqual({ ok: true, text: "small body" });
	});

	it("rejects via Content-Length early check", async () => {
		const req = new Request("https://example.com", {
			method: "POST",
			body: "x",
			headers: { "Content-Length": "99999" },
		});
		const result = await readBodyWithLimit(req, 100);
		expect(result).toEqual({ ok: false });
	});

	it("rejects via streaming when body exceeds limit", async () => {
		const req = new Request("https://example.com", {
			method: "POST",
			body: "x".repeat(200),
		});
		const result = await readBodyWithLimit(req, 100);
		expect(result).toEqual({ ok: false });
	});
});
