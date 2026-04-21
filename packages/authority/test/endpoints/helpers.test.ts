import { type FederationError, FederationErrorCode, InternalErrorCode } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import {
	errorResponse,
	extractRequestParams,
	jsonResponse,
	jwtResponse,
	parseQueryParams,
	requireMethod,
	requireMethods,
	SECURITY_HEADERS,
	toPublicError,
} from "../../src/endpoints/helpers.js";

describe("SECURITY_HEADERS", () => {
	it("includes Cache-Control no-store", () => {
		expect(SECURITY_HEADERS["Cache-Control"]).toBe("no-store");
	});

	it("includes X-Content-Type-Options nosniff", () => {
		expect(SECURITY_HEADERS["X-Content-Type-Options"]).toBe("nosniff");
	});

	it("includes Strict-Transport-Security", () => {
		expect(SECURITY_HEADERS["Strict-Transport-Security"]).toMatch(/max-age=\d+/);
	});

	it("includes X-Frame-Options DENY", () => {
		expect(SECURITY_HEADERS["X-Frame-Options"]).toBe("DENY");
	});

	it("includes Referrer-Policy no-referrer", () => {
		expect(SECURITY_HEADERS["Referrer-Policy"]).toBe("no-referrer");
	});
});

describe("jwtResponse", () => {
	it("returns 200 with correct content type and body", () => {
		const res = jwtResponse("jwt.token.here", "application/entity-statement+jwt");
		expect(res.status).toBe(200);
		expect(res.headers.get("Content-Type")).toBe("application/entity-statement+jwt");
	});

	it("includes security headers", async () => {
		const res = jwtResponse("jwt.token.here", "application/entity-statement+jwt");
		expect(res.headers.get("Cache-Control")).toBe("no-store");
		expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
		expect(res.headers.get("Strict-Transport-Security")).toBeTruthy();
	});

	it("returns the JWT as the body", async () => {
		const res = jwtResponse("my.jwt.token", "application/entity-statement+jwt");
		const body = await res.text();
		expect(body).toBe("my.jwt.token");
	});
});

describe("jsonResponse", () => {
	it("returns JSON with correct content type", async () => {
		const res = jsonResponse({ foo: "bar" });
		expect(res.status).toBe(200);
		expect(res.headers.get("Content-Type")).toBe("application/json");
		const body = await res.json();
		expect(body).toEqual({ foo: "bar" });
	});

	it("includes security headers", () => {
		const res = jsonResponse([]);
		expect(res.headers.get("Cache-Control")).toBe("no-store");
		expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
	});

	it("supports custom status code", () => {
		const res = jsonResponse({ error: "test" }, 400);
		expect(res.status).toBe(400);
	});
});

describe("errorResponse", () => {
	it("returns error JSON with code", async () => {
		const res = errorResponse(400, "invalid_request", "Missing sub");
		expect(res.status).toBe(400);
		const body = await res.json();
		expect(body).toEqual({
			error: "invalid_request",
			error_description: "Missing sub",
		});
	});

	it("omits error_description when not provided", async () => {
		const res = errorResponse(500, "server_error");
		const body = await res.json();
		expect(body).toEqual({ error: "server_error" });
		expect(body.error_description).toBeUndefined();
	});

	it("includes security headers", () => {
		const res = errorResponse(404, "not_found");
		expect(res.headers.get("Cache-Control")).toBe("no-store");
		expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
	});
});

describe("toPublicError", () => {
	it("passes through public federation error codes", () => {
		const err: FederationError = {
			code: FederationErrorCode.InvalidRequest,
			description: "Missing parameter",
		};
		const result = toPublicError(err);
		expect(result.code).toBe("invalid_request");
		expect(result.description).toBe("Missing parameter");
		expect(result.status).toBe(400);
	});

	it("maps not_found to 404", () => {
		const err: FederationError = {
			code: FederationErrorCode.NotFound,
			description: "Entity not found",
		};
		const result = toPublicError(err);
		expect(result.status).toBe(404);
		expect(result.code).toBe("not_found");
	});

	it("sanitizes internal error codes to server_error", () => {
		const err: FederationError = {
			code: InternalErrorCode.SignatureInvalid,
			description: "HMAC mismatch at byte 47 of key material",
		};
		const result = toPublicError(err);
		expect(result.code).toBe("server_error");
		expect(result.status).toBe(500);
		expect(result.description).toBe("An internal error occurred");
		expect(result.description).not.toContain("HMAC");
	});

	it("sanitizes unknown error codes to server_error", () => {
		const err: FederationError = {
			code: "some_unknown_code" as FederationErrorCode,
			description: "Secret internal details",
		};
		const result = toPublicError(err);
		expect(result.code).toBe("server_error");
		expect(result.description).toBe("An internal error occurred");
	});

	it("maps temporarily_unavailable to 503", () => {
		const err: FederationError = {
			code: FederationErrorCode.TemporarilyUnavailable,
			description: "Try again later",
		};
		const result = toPublicError(err);
		expect(result.status).toBe(503);
	});
});

describe("parseQueryParams", () => {
	it("extracts query parameters from request", () => {
		const req = new Request(
			"https://example.com/path?sub=https%3A%2F%2Ffoo.com&type=openid_provider",
		);
		const params = parseQueryParams(req);
		expect(params.get("sub")).toBe("https://foo.com");
		expect(params.get("type")).toBe("openid_provider");
	});

	it("returns empty params for no query string", () => {
		const req = new Request("https://example.com/path");
		const params = parseQueryParams(req);
		expect(params.toString()).toBe("");
	});
});

describe("requireMethod", () => {
	it("returns null when method matches", () => {
		const req = new Request("https://example.com", { method: "GET" });
		expect(requireMethod(req, "GET")).toBeNull();
	});

	it("returns 405 when method does not match", async () => {
		const req = new Request("https://example.com", { method: "POST" });
		const res = requireMethod(req, "GET");
		expect(res).not.toBeNull();
		expect(res?.status).toBe(405);
		expect(res?.headers.get("Allow")).toBe("GET");
	});

	it("includes security headers on 405", () => {
		const req = new Request("https://example.com", { method: "DELETE" });
		const res = requireMethod(req, "POST");
		expect(res?.headers.get("Cache-Control")).toBe("no-store");
		expect(res?.headers.get("X-Content-Type-Options")).toBe("nosniff");
	});

	it("is case-insensitive", () => {
		const req = new Request("https://example.com", { method: "get" });
		expect(requireMethod(req, "GET")).toBeNull();
	});
});

describe("requireMethods", () => {
	it("returns null when method matches any listed method", () => {
		const req = new Request("https://example.com", { method: "POST" });
		expect(requireMethods(req, ["GET", "POST"])).toBeNull();
	});

	it("returns null for GET when GET is listed", () => {
		const req = new Request("https://example.com", { method: "GET" });
		expect(requireMethods(req, ["GET", "POST"])).toBeNull();
	});

	it("returns 405 when method is not listed", async () => {
		const req = new Request("https://example.com", { method: "DELETE" });
		const res = requireMethods(req, ["GET", "POST"]);
		expect(res).not.toBeNull();
		expect(res?.status).toBe(405);
		expect(res?.headers.get("Allow")).toBe("GET, POST");
	});

	it("includes security headers on 405", () => {
		const req = new Request("https://example.com", { method: "PUT" });
		const res = requireMethods(req, ["GET"]);
		expect(res?.headers.get("Cache-Control")).toBe("no-store");
		expect(res?.headers.get("X-Content-Type-Options")).toBe("nosniff");
	});
});

describe("extractRequestParams", () => {
	it("extracts params from GET query string", async () => {
		const req = new Request(
			"https://example.com/path?sub=https%3A%2F%2Ffoo.com&type=openid_provider",
		);
		const result = await extractRequestParams(req);
		expect(result.params.get("sub")).toBe("https://foo.com");
		expect(result.params.get("type")).toBe("openid_provider");
		expect(result.clientAssertion).toBeUndefined();
		expect(result.clientAssertionType).toBeUndefined();
	});

	it("extracts params from POST body", async () => {
		const req = new Request("https://example.com/path", {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: "sub=https%3A%2F%2Ffoo.com&type=openid_provider",
		});
		const result = await extractRequestParams(req);
		expect(result.params.get("sub")).toBe("https://foo.com");
		expect(result.params.get("type")).toBe("openid_provider");
		expect(result.clientAssertion).toBeUndefined();
	});

	it("separates client_assertion fields from POST body", async () => {
		const req = new Request("https://example.com/path", {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: "sub=https%3A%2F%2Ffoo.com&client_assertion=jwt.token.here&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer",
		});
		const result = await extractRequestParams(req);
		expect(result.params.get("sub")).toBe("https://foo.com");
		expect(result.params.has("client_assertion")).toBe(false);
		expect(result.params.has("client_assertion_type")).toBe(false);
		expect(result.clientAssertion).toBe("jwt.token.here");
		expect(result.clientAssertionType).toBe(
			"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		);
	});
});
