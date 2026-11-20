import { cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, describe, expect, it } from "vitest";
import { IssuerTrustCard } from "@/features/trust-marks/components/issuer-trust-card";

afterEach(cleanup);

describe("IssuerTrustCard", () => {
	it("reports a discovered chain and links to its Trust Anchor", () => {
		render(
			<MemoryRouter>
				<IssuerTrustCard
					issuerTrusted={true}
					issuerChainError={null}
					trustedByTA="https://ta.example"
				/>
			</MemoryRouter>,
		);

		expect(screen.getByText("Issuer chain discovery")).toBeTruthy();
		expect(screen.getByText("Chain found")).toBeTruthy();
		expect(screen.getByRole("button", { name: "https://ta.example" })).toBeTruthy();
	});

	it("reports an unavailable chain and shows its diagnostic", () => {
		render(
			<IssuerTrustCard
				issuerTrusted={false}
				issuerChainError="Unable to fetch the issuer"
				trustedByTA={null}
			/>,
		);

		expect(screen.getByText("Chain unavailable")).toBeTruthy();
		expect(screen.getByText("Unable to fetch the issuer")).toBeTruthy();
	});

	it("omits the card when discovery was not attempted", () => {
		const { container } = render(
			<IssuerTrustCard issuerTrusted={null} issuerChainError={null} trustedByTA={null} />,
		);
		expect(container.firstChild).toBeNull();
	});
});
