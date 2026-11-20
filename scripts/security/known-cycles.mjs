/** Existing runtime cycles connect validation and accreditation. New cycles fail the architecture check. */

export const knownCycles = [
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
		"trust-marks/issuer-selection.ts",
		"trust-marks/evidence.ts",
		"trust-chain/resolve.ts",
		"trust-chain/assessment.ts",
		"trust-chain/discovery.ts",
		"trust-chain/validate.ts",
		"trust-marks/evaluate.ts",
	],
];
