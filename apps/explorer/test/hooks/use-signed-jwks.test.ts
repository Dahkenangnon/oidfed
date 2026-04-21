import { act, renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useSignedJwks } from "@/features/entity-inspector/hooks/use-signed-jwks";

vi.mock("@oidfed/core", () => ({
	verifyHistoricalKeysResponse: vi.fn().mockResolvedValue({
		ok: true,
		value: {
			iss: "https://op.test",
			iat: 1000,
			keys: [{ kid: "s1", kty: "EC", exp: 9999999999, iat: 1000 }],
		},
	}),
}));

let fetchSpy: ReturnType<typeof vi.spyOn>;

describe("useSignedJwks", () => {
	afterEach(() => {
		fetchSpy?.mockRestore();
	});

	it("returns null keys initially", () => {
		const { result } = renderHook(() => useSignedJwks("https://op.test/signed_jwks", { keys: [] }));
		expect(result.current.keys).toBeNull();
		expect(result.current.signatureValid).toBeNull();
	});

	it("does not fetch when uri is undefined", () => {
		fetchSpy = vi
			.spyOn(globalThis, "fetch")
			.mockResolvedValue(new Response("mock", { status: 200 }));
		const { result } = renderHook(() => useSignedJwks(undefined, { keys: [] }));
		act(() => result.current.fetch());
		expect(globalThis.fetch).not.toHaveBeenCalled();
	});

	it("fetches and returns keys", async () => {
		fetchSpy = vi
			.spyOn(globalThis, "fetch")
			.mockResolvedValue(new Response("signed.jwt.token", { status: 200 }));
		const { result } = renderHook(() =>
			useSignedJwks("https://op.test/signed_jwks", { keys: [{ kty: "EC" }] }),
		);

		await act(async () => {
			result.current.fetch();
		});

		expect(result.current.keys).toHaveLength(1);
		expect(result.current.signatureValid).toBe(true);
	});

	it("handles HTTP errors", async () => {
		fetchSpy = vi
			.spyOn(globalThis, "fetch")
			.mockResolvedValue(new Response("Not Found", { status: 404, statusText: "Not Found" }));

		const { result } = renderHook(() => useSignedJwks("https://op.test/signed_jwks", { keys: [] }));

		await act(async () => {
			result.current.fetch();
		});

		expect(result.current.error).toBe("HTTP 404: Not Found");
		expect(result.current.signatureValid).toBe(false);
	});
});
