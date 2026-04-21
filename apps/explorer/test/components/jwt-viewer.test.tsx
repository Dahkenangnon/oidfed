import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { JwtViewer } from "@/components/shared/jwt-viewer";

// Mock CodeBlock to render code as plain text
vi.mock("@/components/shared/code-block", () => ({
	CodeBlock: ({ code }: { code: string }) => <pre data-testid="code-block">{code}</pre>,
}));

vi.mock("@/components/shared/copy-button", () => ({
	CopyButton: () => <button type="button">copy</button>,
}));

vi.mock("@oidfed/ui", () => ({
	Tabs: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
	TabsList: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
	TabsTrigger: ({ children, value }: { children: React.ReactNode; value: string }) => (
		<button type="button" data-value={value}>
			{children}
		</button>
	),
	TabsContent: ({ children, value }: { children: React.ReactNode; value: string }) => (
		<div data-tab={value}>{children}</div>
	),
}));

function makeJwt(header: object, payload: object): string {
	const encode = (obj: object) =>
		btoa(JSON.stringify(obj)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
	return `${encode(header)}.${encode(payload)}.fakesignature`;
}

describe("JwtViewer", () => {
	afterEach(() => {
		cleanup();
	});

	it("renders decoded header and payload for valid JWT", () => {
		const jwt = makeJwt({ alg: "RS256", typ: "JWT" }, { sub: "test", iss: "issuer" });
		render(<JwtViewer jwt={jwt} />);

		const blocks = screen.getAllByTestId("code-block");
		expect(blocks.length).toBe(2);
		expect(blocks[0].textContent).toContain('"alg"');
		expect(blocks[1].textContent).toContain('"sub"');
	});

	it("renders content type when provided", () => {
		const jwt = makeJwt({ alg: "RS256" }, { sub: "x" });
		render(<JwtViewer jwt={jwt} contentType="application/entity-statement+jwt" />);
		expect(screen.getByText("application/entity-statement+jwt")).toBeDefined();
	});

	it("handles malformed JWT gracefully", () => {
		expect(() => render(<JwtViewer jwt="not-a-jwt" />)).not.toThrow();
	});
});
