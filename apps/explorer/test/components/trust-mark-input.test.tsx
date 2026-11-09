import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { TrustMarkInput } from "@/features/trust-marks/components/trust-mark-input";

afterEach(() => {
	cleanup();
	localStorage.clear();
});

it("requires an independently entered subject and passes its exact value to inspection", () => {
	const onSubmit = vi.fn();
	render(<TrustMarkInput onSubmit={onSubmit} />);
	fireEvent.change(screen.getByLabelText("Trust Mark JWT"), {
		target: { value: "header.payload.signature" },
	});
	const button = screen.getByRole("button", { name: "Inspect" }) as HTMLButtonElement;
	expect(button.disabled).toBe(true);
	fireEvent.change(screen.getByLabelText("Expected subject Entity ID"), {
		target: { value: "https://MEMBER.example/path" },
	});
	expect(button.disabled).toBe(false);
	fireEvent.click(button);
	expect(onSubmit).toHaveBeenCalledWith("header.payload.signature", "https://MEMBER.example/path");
});
