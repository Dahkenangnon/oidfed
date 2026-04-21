import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CopyButton } from "@/components/shared/copy-button";

// Mock Base UI Tooltip to render children directly
vi.mock("@oidfed/ui", () => ({
	Tooltip: ({ children }: { children: React.ReactNode }) => <>{children}</>,
	TooltipTrigger: ({
		children,
		render: renderProp,
	}: {
		children: React.ReactNode;
		render: React.ReactElement;
	}) => (
		<button type="button" {...(renderProp?.props ?? {})}>
			{children}
		</button>
	),
	TooltipPopup: ({ children }: { children: React.ReactNode }) => <span>{children}</span>,
	Button: ({ children, ...props }: Record<string, unknown>) => (
		<button type="button" {...props}>
			{children as React.ReactNode}
		</button>
	),
}));

describe("CopyButton", () => {
	afterEach(() => {
		cleanup();
		vi.restoreAllMocks();
	});

	it("renders with copy label", () => {
		render(<CopyButton value="test" />);
		expect(screen.getByLabelText("Copy to clipboard")).toBeDefined();
	});

	it("calls clipboard API on click", async () => {
		const writeText = vi.fn().mockResolvedValue(undefined);
		Object.assign(navigator, { clipboard: { writeText } });

		render(<CopyButton value="hello" />);
		fireEvent.click(screen.getByLabelText("Copy to clipboard"));

		expect(writeText).toHaveBeenCalledWith("hello");
	});

	it("handles clipboard rejection gracefully", () => {
		const writeText = vi.fn().mockRejectedValue(new Error("denied"));
		Object.assign(navigator, { clipboard: { writeText } });

		render(<CopyButton value="test" />);
		// Should not throw
		expect(() => fireEvent.click(screen.getByLabelText("Copy to clipboard"))).not.toThrow();
	});
});
