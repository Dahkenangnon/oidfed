import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { PolicySimulatorPage } from "@/features/policy/page";

describe("PolicySimulatorPage", () => {
	beforeEach(() => localStorage.clear());
	afterEach(() => {
		cleanup();
		localStorage.clear();
	});

	it("shows malformed metadata errors and recovers when the entity type is an object", () => {
		render(<PolicySimulatorPage />);
		const metadata = screen.getByLabelText("Leaf Entity Metadata (JSON object)");
		const policy = screen.getByPlaceholderText(
			'{"openid_relying_party": {"redirect_uris": {"subset_of": ["https://example.com/cb"]}}}',
		);
		fireEvent.change(metadata, { target: { value: '{"openid_relying_party":null}' } });
		fireEvent.change(policy, {
			target: { value: '{"openid_relying_party":{"client_name":{"default":"RP"}}}' },
		});
		expect(
			screen.getByText(/Policy apply error:.*openid_relying_party.*JSON object/),
		).toBeDefined();
		expect(screen.getByLabelText("Leaf Entity Metadata (JSON object)")).toBe(metadata);

		fireEvent.change(metadata, { target: { value: '{"openid_relying_party":{}}' } });
		expect(screen.queryByText(/Policy apply error:/)).toBeNull();
		expect(screen.getByRole("tab", { name: "Resolved Metadata" })).toBeDefined();
	});
});
