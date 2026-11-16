/** Existing runtime cycles connect validation, accreditation, and transport. New cycles fail the architecture check. */

export const knownCycles = [
	["trust-chain/fetch.ts", "endpoint-client.ts"],
	["federation-api/index.ts", "federation-api/fetch-historical-keys.ts"],
	["trust-chain/discovery.ts", "trust-chain/resolve.ts", "trust-chain/assessment.ts"],
	[
		"trust-chain/validate.ts",
		"trust-marks/evaluate.ts",
		"trust-marks/evidence.ts",
		"trust-chain/resolve.ts",
		"trust-chain/assessment.ts",
	],
	[
		"trust-chain/validate.ts",
		"trust-marks/evaluate.ts",
		"trust-marks/evidence.ts",
		"trust-chain/resolve.ts",
		"trust-chain/assessment.ts",
		"trust-chain/discovery.ts",
	],
	[
		"trust-chain/validate.ts",
		"trust-marks/evaluate.ts",
		"trust-marks/evidence.ts",
		"trust-chain/resolve.ts",
	],
	["trust-marks/evaluate.ts", "trust-marks/evidence.ts", "trust-chain/validate.ts"],
	[
		"trust-marks/index.ts",
		"trust-marks/fetch.ts",
		"trust-marks/evidence.ts",
		"trust-chain/resolve.ts",
		"trust-chain/assessment.ts",
		"trust-chain/discovery.ts",
		"trust-chain/validate.ts",
		"trust-marks/evaluate.ts",
	],
	[
		"trust-marks/issuer-selection.ts",
		"trust-marks/evidence.ts",
		"trust-chain/resolve.ts",
		"trust-chain/assessment.ts",
		"trust-chain/discovery.ts",
		"trust-chain/validate.ts",
		"trust-marks/evaluate.ts",
	],
	["trust-marks/index.ts", "trust-marks/fetch.ts", "trust-marks/evidence.ts"],
];
