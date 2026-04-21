import { act, renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useTrustMarkValidation } from "@/features/entity-inspector/hooks/use-trust-mark-validation";

function fakeJwt(payload: Record<string, unknown>): string {
	const header = btoa(JSON.stringify({ alg: "ES256", typ: "trust-mark+jwt" }));
	const body = btoa(JSON.stringify(payload))
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=/g, "");
	return `${header}.${body}.fakesig`;
}

vi.mock("@oidfed/core", () => ({
	fetchEntityConfiguration: vi.fn().mockResolvedValue({
		ok: true,
		value: "mock.ec.jwt",
	}),
	decodeEntityStatement: vi.fn().mockReturnValue({
		ok: true,
		value: {
			header: { alg: "ES256" },
			payload: {
				iss: "https://ta.test",
				sub: "https://ta.test",
				jwks: { keys: [{ kty: "EC", kid: "k1" }] },
			},
		},
	}),
	validateTrustMark: vi.fn().mockResolvedValue({
		ok: true,
		value: {
			trustMarkType: "https://ta.test/tm/certified",
			issuer: "https://ta.test",
			subject: "https://rp.test",
			issuedAt: 1000,
			expiresAt: undefined,
		},
	}),
	validateEntityId: vi.fn().mockImplementation((id: string) => ({
		ok: true,
		value: id,
	})),
}));

vi.mock("@/hooks/use-settings", () => ({
	useSettings: () => [{ trustAnchors: [], httpTimeoutMs: 10000 }, vi.fn()] as const,
}));

describe("useTrustMarkValidation", () => {
	afterEach(() => {
		vi.clearAllMocks();
	});

	it("starts in idle status", () => {
		const jwt = fakeJwt({ iss: "https://ta.test", id: "https://ta.test/tm/certified" });
		const { result } = renderHook(() => useTrustMarkValidation(jwt));
		expect(result.current.status).toBe("idle");
		expect(result.current.details).toBeNull();
	});

	it("validates a trust mark successfully", async () => {
		const jwt = fakeJwt({ iss: "https://ta.test", id: "https://ta.test/tm/certified" });
		const { result } = renderHook(() => useTrustMarkValidation(jwt));

		await act(async () => {
			result.current.verify();
		});

		expect(result.current.status).toBe("valid");
		expect(result.current.details?.issuer).toBe("https://ta.test");
	});

	it("handles missing iss claim", async () => {
		const jwt = fakeJwt({ id: "some-type" });
		const { result } = renderHook(() => useTrustMarkValidation(jwt));

		await act(async () => {
			result.current.verify();
		});

		expect(result.current.status).toBe("error");
		expect(result.current.error).toContain("missing iss");
	});

	it("handles malformed JWT", async () => {
		const { result } = renderHook(() => useTrustMarkValidation("not.a.jwt"));

		await act(async () => {
			result.current.verify();
		});

		expect(result.current.status).toBe("error");
	});
});
