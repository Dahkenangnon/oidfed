import { InternalErrorCode, type TrustMarkEvaluation } from "@oidfed/core";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { TrustMarkList } from "../../src/features/trust-chain/components/trust-mark-list";

afterEach(cleanup);

describe("Trust Mark outcomes", () => {
	it("distinguishes verified, invalid and unevaluated marks of the same type", () => {
		const trustMarkType = "https://marks.example/accredited";
		const evaluations: TrustMarkEvaluation[] = [
			{
				referenceIndex: 0,
				trustMarkType,
				status: "verified",
				mark: {
					trustMarkType,
					issuer: "https://issuer.example",
					subject: "https://member.example",
					issuedAt: 1000,
				},
			},
			{
				referenceIndex: 1,
				trustMarkType,
				status: "invalid",
				error: { code: InternalErrorCode.TrustMarkInvalid, description: "Trust Mark has expired" },
			},
			{
				referenceIndex: 2,
				trustMarkType,
				status: "unevaluated",
				reason: "issuer_keys_unavailable",
				description: "Issuer evidence is unavailable",
			},
		];
		render(<TrustMarkList evaluations={evaluations} />);
		expect(screen.getAllByText(trustMarkType)).toHaveLength(3);
		for (const label of [
			"Verified",
			"Invalid",
			"Unevaluated",
			"Trust Mark has expired",
			"Issuer evidence is unavailable",
		]) {
			expect(screen.getByText(label)).toBeTruthy();
		}
	});
	it("distinguishes no published marks from failed evaluation", () => {
		render(<TrustMarkList evaluations={[]} />);
		expect(screen.getByText("No Trust Marks published by the chain subject.")).toBeTruthy();
	});
});
