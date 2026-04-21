import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { JwkTable } from "@/components/shared/jwk-table";

// Mock jwkThumbprint from @oidfed/core (component imports from there, not jose)
vi.mock("@oidfed/core", async () => {
	const actual = await vi.importActual("@oidfed/core");
	return {
		...actual,
		jwkThumbprint: vi.fn().mockImplementation(async (jwk: { kid?: string }) => {
			return `thumb_abcdefghij123456_${jwk.kid ?? "unknown"}`;
		}),
	};
});

// Mock CopyButton
vi.mock("@/components/shared/copy-button", () => ({
	CopyButton: ({ value }: { value: string }) => (
		<button type="button" data-testid="copy-btn" data-value={value}>
			copy
		</button>
	),
}));

describe("JwkTable", () => {
	afterEach(() => {
		cleanup();
	});

	it("shows no keys message when empty", () => {
		render(<JwkTable jwks={{ keys: [] }} />);
		expect(screen.getByText("No keys found.")).toBeDefined();
	});

	it("renders key rows with standard columns", () => {
		render(
			<JwkTable
				jwks={{
					keys: [{ kid: "key-1", kty: "EC", alg: "ES256", use: "sig", crv: "P-256" }],
				}}
			/>,
		);
		expect(screen.getByText("key-1")).toBeDefined();
		expect(screen.getByText("ES256")).toBeDefined();
		expect(screen.getByText("sig")).toBeDefined();
		expect(screen.getByText("P-256")).toBeDefined();
	});

	it("renders thumbprint column header", () => {
		render(<JwkTable jwks={{ keys: [{ kid: "k1", kty: "EC" }] }} />);
		expect(screen.getByText("Thumbprint (SHA-256)")).toBeDefined();
	});

	it("computes and displays truncated thumbprints", async () => {
		render(<JwkTable jwks={{ keys: [{ kid: "k1", kty: "EC" }] }} />);
		// The thumbprint is "thumb_abcdefghij123456_k1", truncated to first 16 chars + "…"
		await waitFor(() => {
			expect(screen.getByText("thumb_abcdefghij…")).toBeDefined();
		});
	});

	it("renders copy button for thumbprints", async () => {
		render(<JwkTable jwks={{ keys: [{ kid: "k1", kty: "EC" }] }} />);
		await waitFor(() => {
			const btn = screen.getByTestId("copy-btn");
			expect(btn.getAttribute("data-value")).toBe("thumb_abcdefghij123456_k1");
		});
	});
});
