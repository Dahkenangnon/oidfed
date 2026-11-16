/** Focused mutation check for authentication-parameter and selector guards. */

import { tmpdir } from "node:os";
import { join } from "node:path";

export default {
	mutate: ["packages/core/src/endpoint-parameters.ts"],
	ignorePatterns: [
		"**",
		"!package.json",
		"!packages/core/src/endpoint-parameters.ts",
		"!tests/security/mutation.test.mjs",
	],
	testRunner: "command",
	commandRunner: { command: "node --import tsx tests/security/mutation.test.mjs" },
	coverageAnalysis: "off",
	concurrency: 2,
	timeoutMS: 5000,
	timeoutFactor: 2,
	reporters: ["clear-text", "json"],
	jsonReporter: { fileName: join(tmpdir(), "oidfed-mutation-report.json") },
	tempDirName: join(tmpdir(), `oidfed-stryker-${process.pid}`),
	cleanTempDir: true,
	thresholds: { high: 99, low: 95, break: 95 },
};
