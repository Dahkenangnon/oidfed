import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { TrustMarkIssuersPanel } from "@/features/entity-inspector/components/trust-mark-issuers";

// Mock entity-link to avoid router dependency
vi.mock("@/components/shared/entity-link", () => ({
	EntityLink: ({ entityId }: { entityId: string }) => (
		<span data-testid="entity-link">{entityId}</span>
	),
}));

describe("TrustMarkIssuersPanel", () => {
	afterEach(() => {
		cleanup();
	});

	it("returns null when both props are absent", () => {
		const { container } = render(<TrustMarkIssuersPanel />);
		expect(container.innerHTML).toBe("");
	});

	it("returns null when both props are empty objects", () => {
		const { container } = render(
			<TrustMarkIssuersPanel trustMarkIssuers={{}} trustMarkOwners={{}} />,
		);
		expect(container.innerHTML).toBe("");
	});

	it("renders issuers table", () => {
		render(
			<TrustMarkIssuersPanel
				trustMarkIssuers={{
					"https://example.com/tm/certified": ["https://ta.example.com"],
				}}
			/>,
		);
		expect(screen.getAllByText("Authorized Issuers").length).toBeGreaterThan(0);
		expect(screen.getByText("https://example.com/tm/certified")).toBeDefined();
		expect(screen.getByText("https://ta.example.com")).toBeDefined();
	});

	it("renders owners table", () => {
		render(
			<TrustMarkIssuersPanel
				trustMarkOwners={{
					"https://example.com/tm/owned": {
						sub: "https://owner.example.com",
						jwks: { keys: [{ kty: "EC" }, { kty: "EC" }] },
					},
				}}
			/>,
		);
		expect(screen.getByText("Trust Mark Owners")).toBeDefined();
		expect(screen.getByText("https://owner.example.com")).toBeDefined();
		expect(screen.getByText("2 keys")).toBeDefined();
	});

	it("renders both sections when both props provided", () => {
		render(
			<TrustMarkIssuersPanel
				trustMarkIssuers={{ "type-a": ["https://issuer.test"] }}
				trustMarkOwners={{
					"type-b": { sub: "https://owner.test", jwks: { keys: [{ kty: "EC" }] } },
				}}
			/>,
		);
		expect(screen.getAllByText("Authorized Issuers").length).toBeGreaterThan(0);
		expect(screen.getAllByText("Trust Mark Owners").length).toBeGreaterThan(0);
	});
});
