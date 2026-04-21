import { act, renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useHistoricalKeys } from "@/features/entity-inspector/hooks/use-historical-keys";

vi.mock("@oidfed/core", () => ({
	verifyHistoricalKeysResponse: vi.fn().mockResolvedValue({
		ok: true,
		value: {
			iss: "https://ta.test",
			iat: 1000,
			keys: [
				{ kid: "k1", kty: "EC", exp: 9999999999, iat: 1000 },
				{ kid: "k2", kty: "EC", exp: 1000 },
			],
		},
	}),
}));

let fetchSpy: ReturnType<typeof vi.spyOn>;

describe("useHistoricalKeys", () => {
	afterEach(() => {
		fetchSpy?.mockRestore();
	});

	it("returns null keys initially", () => {
		const { result } = renderHook(() => useHistoricalKeys("https://ta.test/keys", { keys: [] }));
		expect(result.current.keys).toBeNull();
		expect(result.current.loading).toBe(false);
		expect(result.current.signatureValid).toBeNull();
	});

	it("does not fetch when endpoint is undefined", () => {
		fetchSpy = vi
			.spyOn(globalThis, "fetch")
			.mockResolvedValue(new Response("mock", { status: 200 }));
		const { result } = renderHook(() => useHistoricalKeys(undefined, { keys: [] }));
		act(() => result.current.fetch());
		expect(globalThis.fetch).not.toHaveBeenCalled();
	});

	it("fetches and verifies keys on fetch()", async () => {
		fetchSpy = vi
			.spyOn(globalThis, "fetch")
			.mockResolvedValue(new Response("mock.jwt.token", { status: 200 }));
		const { result } = renderHook(() =>
			useHistoricalKeys("https://ta.test/keys", { keys: [{ kty: "EC" }] }),
		);

		await act(async () => {
			result.current.fetch();
		});

		expect(globalThis.fetch).toHaveBeenCalledWith(
			"https://ta.test/keys",
			expect.objectContaining({
				headers: { Accept: "application/jwk-set+jwt" },
			}),
		);
		expect(result.current.keys).toHaveLength(2);
		expect(result.current.signatureValid).toBe(true);
		expect(result.current.loading).toBe(false);
	});

	it("handles fetch errors", async () => {
		fetchSpy = vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("Network failure"));

		const { result } = renderHook(() => useHistoricalKeys("https://ta.test/keys", { keys: [] }));

		await act(async () => {
			result.current.fetch();
		});

		expect(result.current.error).toBe("Network failure");
		expect(result.current.signatureValid).toBe(false);
	});
});
