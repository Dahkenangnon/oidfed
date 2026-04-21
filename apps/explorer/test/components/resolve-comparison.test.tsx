import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ResolveComparison } from "@/features/resolve/components/resolve-comparison";
import type {
	ResolvePerTaError,
	ResolvePerTaOutcome,
	ResolvePerTaResult,
} from "@/features/resolve/hooks/use-resolve-query";

// Mock UI components to simplify rendering
vi.mock("@oidfed/ui", () => ({
	Tabs: ({ children, ...props }: Record<string, unknown>) => (
		<div data-testid="tabs" data-default-value={props.defaultValue}>
			{children as React.ReactNode}
		</div>
	),
	TabsList: ({ children }: { children: React.ReactNode }) => (
		<div data-testid="tabs-list">{children}</div>
	),
	TabsTrigger: ({ children, value }: { children: React.ReactNode; value: string }) => (
		<button type="button" data-testid={`tab-${value}`}>
			{children}
		</button>
	),
	TabsContent: ({ children, value }: { children: React.ReactNode; value: string }) => (
		<div data-testid={`content-${value}`}>{children}</div>
	),
	Card: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
	CardHeader: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
	CardTitle: ({ children }: { children: React.ReactNode }) => <h3>{children}</h3>,
	CardContent: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
	Badge: ({ children }: { children: React.ReactNode }) => <span>{children}</span>,
}));

vi.mock("@/features/resolve/components/resolve-result", () => ({
	ResolveResult: ({ requestUrl }: { requestUrl: string }) => (
		<div data-testid="resolve-result">{requestUrl}</div>
	),
}));

vi.mock("@/features/trust-chain/components/resolved-metadata-diff", () => ({
	ResolvedMetadataDiff: () => <div data-testid="metadata-diff" />,
}));

vi.mock("@/components/shared/copy-button", () => ({
	CopyButton: () => <button type="button">copy</button>,
}));

const makeSuccess = (ta: string): ResolvePerTaResult => ({
	trustAnchorId: `https://${ta}.example.com`,
	responsePayload: {
		iss: "https://resolver.example.com",
		sub: "https://leaf.example.com",
		iat: 1000,
		exp: 2000,
		metadata: { openid_provider: { issuer: `https://${ta}.example.com` } },
		trust_chain: ["jwt1", "jwt2"],
	} as never,
	requestUrl: `https://resolver.example.com/resolve?sub=leaf&trust_anchor=${ta}`,
});

const makeError = (ta: string): ResolvePerTaError => ({
	trustAnchorId: `https://${ta}.example.com`,
	requestUrl: `https://resolver.example.com/resolve?sub=leaf&trust_anchor=${ta}`,
	error: `Failed for ${ta}`,
});

describe("ResolveComparison", () => {
	afterEach(() => {
		cleanup();
	});

	it("renders single success result directly", () => {
		const results: ResolvePerTaOutcome[] = [makeSuccess("ta1")];
		render(<ResolveComparison results={results} />);
		expect(screen.getByTestId("resolve-result")).toBeDefined();
	});

	it("renders single error result with error message", () => {
		const results: ResolvePerTaOutcome[] = [makeError("ta1")];
		render(<ResolveComparison results={results} />);
		expect(screen.getByText("Failed for ta1")).toBeDefined();
	});

	it("renders tabs for multiple results", () => {
		const results: ResolvePerTaOutcome[] = [makeSuccess("ta1"), makeSuccess("ta2")];
		render(<ResolveComparison results={results} />);
		expect(screen.getByTestId("tab-https://ta1.example.com")).toBeDefined();
		expect(screen.getByTestId("tab-https://ta2.example.com")).toBeDefined();
	});

	it("shows Compare tab when 2+ successes", () => {
		const results: ResolvePerTaOutcome[] = [makeSuccess("ta1"), makeSuccess("ta2")];
		render(<ResolveComparison results={results} />);
		expect(screen.getByTestId("tab-__compare__")).toBeDefined();
	});

	it("hides Compare tab with only 1 success", () => {
		const results: ResolvePerTaOutcome[] = [makeSuccess("ta1"), makeError("ta2")];
		render(<ResolveComparison results={results} />);
		expect(screen.queryByTestId("tab-__compare__")).toBeNull();
	});

	it("shows resolution summary with counts", () => {
		const results: ResolvePerTaOutcome[] = [
			makeSuccess("ta1"),
			makeSuccess("ta2"),
			makeError("ta3"),
		];
		render(<ResolveComparison results={results} />);
		expect(screen.getByText("2 resolved")).toBeDefined();
		expect(screen.getByText("1 failed")).toBeDefined();
	});

	it("renders metadata diff in compare tab", () => {
		const results: ResolvePerTaOutcome[] = [makeSuccess("ta1"), makeSuccess("ta2")];
		render(<ResolveComparison results={results} />);
		expect(screen.getByTestId("metadata-diff")).toBeDefined();
	});

	it("returns null for empty results", () => {
		const { container } = render(<ResolveComparison results={[]} />);
		expect(container.innerHTML).toBe("");
	});
});
