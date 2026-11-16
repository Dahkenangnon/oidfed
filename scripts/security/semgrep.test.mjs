/** Keep transport detection active across equivalent paths in separate scan targets. */

import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { semgrepBin } from "./install.mjs";
import { root } from "./scope.mjs";

test("unbounded fetch calls remain detected at transport paths in every package", async () => {
	const temporary = await mkdtemp(join(tmpdir(), "oidfed-transport-rule-"));
	try {
		const targets = ["packages/core/src", "packages/wallet/src"];
		for (const target of targets) {
			await mkdir(join(temporary, target, "trust-chain"), { recursive: true });
			await writeFile(
				join(temporary, target, "trust-chain/fetch.ts"),
				'fetch("https://entity.example");\nglobalThis.fetch("https://entity.example");\n',
			);
		}
		const result = spawnSync(
			join(semgrepBin, "semgrep"),
			[
				"scan",
				"--metrics",
				"off",
				"--disable-version-check",
				"--error",
				"--json",
				"--config",
				join(root, "scripts/security/semgrep.yml"),
				...targets,
			],
			{
				cwd: temporary,
				env: {
					...process.env,
					SEMGREP_SETTINGS_FILE: join(temporary, "settings.yml"),
					SEMGREP_LOG_FILE: join(temporary, "semgrep.log"),
					SEMGREP_SEND_METRICS: "off",
					SEMGREP_ENABLE_VERSION_CHECK: "0",
				},
				encoding: "utf8",
			},
		);
		assert.equal(result.status, 1, result.stderr);
		const report = JSON.parse(result.stdout);
		assert.deepEqual(report.errors, []);
		const findings = report.results.filter((entry) =>
			entry.check_id.endsWith("no-unbounded-fetch"),
		);
		for (const target of targets)
			assert.deepEqual(
				findings
					.filter((entry) => entry.path === `${target}/trust-chain/fetch.ts`)
					.map((entry) => entry.start.line),
				[1, 2],
			);
	} finally {
		await rm(temporary, { recursive: true, force: true });
	}
});
