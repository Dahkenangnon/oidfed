import { describe, expect, it } from "vitest";
import {
	err,
	federationError,
	flatMap,
	isErr,
	isOk,
	map,
	mapErr,
	ok,
	type Result,
	unwrapOr,
} from "../src/errors.js";

describe("federationError", () => {
	it("creates an error with code and description", () => {
		const e = federationError("invalid_request", "bad input");
		expect(e.code).toBe("invalid_request");
		expect(e.description).toBe("bad input");
		expect(e.cause).toBeUndefined();
	});

	it("includes cause when provided", () => {
		const cause = new Error("root");
		const e = federationError("server_error", "something broke", cause);
		expect(e.cause).toBe(cause);
	});
});

describe("Result pattern", () => {
	it("ok() creates a successful result", () => {
		const result = ok(42);
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.value).toBe(42);
		}
	});

	it("err() creates a failure result", () => {
		const result = err("failure");
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error).toBe("failure");
		}
	});

	it("isOk() type guard works", () => {
		const success: Result<number, string> = ok(1);
		const failure: Result<number, string> = err("fail");

		expect(isOk(success)).toBe(true);
		expect(isOk(failure)).toBe(false);
	});

	it("isErr() type guard works", () => {
		const success: Result<number, string> = ok(1);
		const failure: Result<number, string> = err("fail");

		expect(isErr(success)).toBe(false);
		expect(isErr(failure)).toBe(true);
	});

	it("map() transforms value on success", () => {
		const result: Result<number, string> = ok(2);
		const mapped = map(result, (v) => v * 3);
		expect(isOk(mapped) && mapped.value).toBe(6);
	});

	it("map() passes through error on failure", () => {
		const result: Result<number, string> = err("fail");
		const mapped = map(result, (v) => v * 3);
		expect(isErr(mapped) && mapped.error).toBe("fail");
	});

	it("flatMap() chains successful results", () => {
		const result: Result<number, string> = ok(5);
		const chained = flatMap(result, (v) => (v > 0 ? ok(v.toString()) : err("negative")));
		expect(isOk(chained) && chained.value).toBe("5");
	});

	it("flatMap() short-circuits on error", () => {
		const result: Result<number, string> = err("initial");
		const chained = flatMap(result, (v) => ok(v.toString()));
		expect(isErr(chained) && chained.error).toBe("initial");
	});

	it("flatMap() can produce error from ok value", () => {
		const result: Result<number, string> = ok(-1);
		const chained = flatMap(result, (v) => (v > 0 ? ok(v.toString()) : err("negative")));
		expect(isErr(chained) && chained.error).toBe("negative");
	});

	it("mapErr() transforms error on failure", () => {
		const result: Result<number, string> = err("fail");
		const mapped = mapErr(result, (e) => e.toUpperCase());
		expect(isErr(mapped) && mapped.error).toBe("FAIL");
	});

	it("mapErr() passes through value on success", () => {
		const result: Result<number, string> = ok(42);
		const mapped = mapErr(result, (e) => e.toUpperCase());
		expect(isOk(mapped) && mapped.value).toBe(42);
	});

	it("unwrapOr() returns value on success", () => {
		const result: Result<number, string> = ok(42);
		expect(unwrapOr(result, 0)).toBe(42);
	});

	it("unwrapOr() returns fallback on failure", () => {
		const result: Result<number, string> = err("fail");
		expect(unwrapOr(result, 0)).toBe(0);
	});
});
