import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, describe, expect, it } from "vitest";
import { ExpiryTable } from "@/features/expiry/components/expiry-table";
import type { ExpiryEntry } from "@/features/expiry/hooks/use-expiry-scan";

describe("ExpiryTable", () => {
	afterEach(cleanup);

	it("preserves the focused sort button while toggling entity order", () => {
		const entries: ExpiryEntry[] = [
			{
				entityId: "https://zeta.example",
				trustAnchorId: "https://anchor.example",
				expiresAt: 100,
				daysRemaining: 20,
				expired: false,
			},
			{
				entityId: "https://alpha.example",
				trustAnchorId: "https://anchor.example",
				expiresAt: 200,
				daysRemaining: 30,
				expired: false,
			},
		];
		render(
			<MemoryRouter>
				<ExpiryTable entries={entries} />
			</MemoryRouter>,
		);
		const header = screen.getByRole("button", { name: "Entity ID" });
		const entityOrder = () =>
			screen
				.getAllByRole("row")
				.slice(1)
				.map((row) => within(row).getAllByRole("cell")[0]?.textContent);
		header.focus();
		fireEvent.click(header);
		expect(document.activeElement).toBe(header);
		expect(entityOrder()).toEqual(["https://alpha.example", "https://zeta.example"]);

		fireEvent.click(header);
		expect(document.activeElement).toBe(header);
		expect(entityOrder()).toEqual(["https://zeta.example", "https://alpha.example"]);
	});
});
