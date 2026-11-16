/** Verify interpreter selection and hash enforcement with isolated, offline wheel fixtures. */

import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, readFile, copyFile, rm, access } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { semgrepRequirements } from "./install.mjs";
import { root } from "./scope.mjs";

test("Semgrep selects only the three supported Python hash locks", () => {
	for (const minor of [12, 13, 14])
		assert.ok(semgrepRequirements(`3.${minor}`).endsWith(`semgrep-py3${minor}.txt`));
	for (const version of ["3.11", "3.15", "4.0", "3.14/../../other", undefined])
		assert.throws(() => semgrepRequirements(version), /requires Python 3.12–3.14/);
});

test("committed locks pin and hash every Semgrep dependency without remote installer options", async () => {
	const input = (
		await readFile(join(root, "scripts/security/requirements/semgrep.in"), "utf8")
	).trim();
	for (const minor of [12, 13, 14]) {
		const lock = await readFile(semgrepRequirements(`3.${minor}`), "utf8");
		const entries = lock
			.replace(/\\\r?\n/g, " ")
			.split("\n")
			.map((line) => line.trim())
			.filter((line) => line && !line.startsWith("#"));
		assert.ok(entries.length > 40, "the lock contains the resolved transitive graph");
		assert.ok(entries.some((line) => line.startsWith(`${input} `)));
		for (const entry of entries) {
			if (entry === "--only-binary :all:") continue;
			assert.match(
				entry,
				/^[a-z0-9_.-]+(?:\[[a-z0-9_,.-]+\])?==[^\s]+(?:\s+--hash=sha256:[a-f0-9]{64})+$/i,
			);
		}
	}
});

async function fixture() {
	const temporary = await mkdtemp(join(tmpdir(), "oidfed-hashed-installer-"));
	const scripts = join(temporary, "scripts/security");
	await mkdir(join(scripts, "requirements"), { recursive: true });
	for (const file of ["install.mjs", "scope.mjs"])
		await copyFile(join(root, "scripts/security", file), join(scripts, file));
	await writeFile(join(temporary, "package.json"), '{"type":"module"}');
	const wheels = join(temporary, "wheels");
	await mkdir(wheels);
	const generated = spawnSync(
		"python3",
		[
			"-c",
			`
import pathlib, sys, zipfile
directory = pathlib.Path(sys.argv[1])
for name, version in [('semgrep', '1.185.0'), ('fixture_dependency', '1.0.0')]:
    dist = f'{name}-{version}.dist-info'
    with zipfile.ZipFile(directory / f'{name}-{version}-py3-none-any.whl', 'w') as wheel:
        wheel.writestr(f'{name}/__init__.py', '')
        wheel.writestr(f'{dist}/WHEEL', 'Wheel-Version: 1.0\\nGenerator: fixture\\nRoot-Is-Purelib: true\\nTag: py3-none-any\\n')
        metadata = f'Metadata-Version: 2.1\\nName: {name.replace("_", "-")}\\nVersion: {version}\\n'
        if name == 'semgrep':
            metadata += 'Requires-Dist: fixture-dependency==1.0.0\\n'
            wheel.writestr('semgrep/cli.py', 'def main():\\n    print("1.185.0")\\n')
            wheel.writestr(f'{dist}/entry_points.txt', '[console_scripts]\\nsemgrep = semgrep.cli:main\\n')
        wheel.writestr(f'{dist}/METADATA', metadata)
        wheel.writestr(f'{dist}/RECORD', '')
print(f'{sys.version_info.major}.{sys.version_info.minor}')
`,
			wheels,
		],
		{ encoding: "utf8" },
	);
	assert.equal(generated.status, 0, generated.stderr);
	const minor = generated.stdout.trim();
	semgrepRequirements(minor);
	const hash = async (file) =>
		createHash("sha256")
			.update(await readFile(join(wheels, file)))
			.digest("hex");
	const semgrepHash = await hash("semgrep-1.185.0-py3-none-any.whl");
	const dependencyHash = await hash("fixture_dependency-1.0.0-py3-none-any.whl");
	const requirements = join(scripts, "requirements", `semgrep-py${minor.replace(".", "")}.txt`);
	const environment = join(temporary, "generated-semgrep");
	return {
		temporary,
		environment,
		wheels,
		requirements,
		semgrepHash,
		dependencyHash,
		async lock(dependency = `fixture-dependency==1.0.0 --hash=sha256:${dependencyHash}`) {
			await writeFile(
				requirements,
				`semgrep==1.185.0 --hash=sha256:${semgrepHash}\n${dependency}\n`,
			);
		},
		run(python = "python3") {
			return spawnSync(
				process.execPath,
				[
					"--input-type=module",
					"-e",
					'import {installSemgrep} from "./scripts/security/install.mjs"; await installSemgrep(process.env.FIXTURE_PYTHON, process.env.FIXTURE_ENVIRONMENT);',
				],
				{
					cwd: temporary,
					env: {
						...process.env,
						FIXTURE_PYTHON: python,
						FIXTURE_ENVIRONMENT: environment,
						PIP_CONFIG_FILE: "/dev/null",
						PIP_NO_INDEX: "1",
						PIP_FIND_LINKS: wheels,
						PIP_CACHE_DIR: join(temporary, "pip-cache"),
						PIP_DISABLE_PIP_VERSION_CHECK: "1",
					},
					encoding: "utf8",
				},
			);
		},
	};
}

test("a clean hash-locked install replaces an existing unlocked environment", async () => {
	const f = await fixture();
	try {
		await f.lock();
		await mkdir(f.environment);
		const stale = join(f.environment, "unlocked-package-marker");
		await writeFile(stale, "must be removed");
		const result = f.run();
		assert.equal(result.status, 0, result.stderr);
		assert.match(result.stdout, /No broken requirements found/);
		assert.match(result.stdout, /Installed Semgrep 1.185.0 from verified wheels/);
		await assert.rejects(access(stale));
	} finally {
		await rm(f.temporary, { recursive: true, force: true });
	}
});

test("tampered wheels and dependencies without hashes fail installation", async () => {
	for (const mode of ["tampered", "unhashed", "missing"]) {
		const f = await fixture();
		try {
			await f.lock(
				mode === "unhashed" ? "fixture-dependency==1.0.0" : mode === "missing" ? "" : undefined,
			);
			if (mode === "tampered")
				await writeFile(join(f.wheels, "semgrep-1.185.0-py3-none-any.whl"), "modified artifact");
			const result = f.run();
			assert.notEqual(result.status, 0, mode);
			assert.match(result.stderr, /hash|Hashes/);
			assert.doesNotMatch(result.stdout, /Installed Semgrep .* from verified wheels/);
		} finally {
			await rm(f.temporary, { recursive: true, force: true });
		}
	}
});

test("unsupported interpreters reject before changing the managed environment", async () => {
	const f = await fixture();
	try {
		const python = join(f.temporary, "unsupported-python");
		await writeFile(python, `#!${process.execPath}\nconsole.log("3.11");\n`, { mode: 0o755 });
		await mkdir(f.environment);
		const marker = join(f.environment, "untouched");
		await writeFile(marker, "original");
		const result = f.run(python);
		assert.notEqual(result.status, 0);
		assert.match(result.stderr, /requires Python 3.12–3.14/);
		assert.equal(await readFile(marker, "utf8"), "original");
	} finally {
		await rm(f.temporary, { recursive: true, force: true });
	}
});

test("a source distribution cannot replace an unavailable wheel", async () => {
	const f = await fixture();
	try {
		await rm(join(f.wheels, "fixture_dependency-1.0.0-py3-none-any.whl"));
		const source = Buffer.from("source builds must not execute");
		await writeFile(join(f.wheels, "fixture_dependency-1.0.0.tar.gz"), source);
		await f.lock(
			`fixture-dependency==1.0.0 --hash=sha256:${createHash("sha256").update(source).digest("hex")}`,
		);
		const result = f.run();
		assert.notEqual(result.status, 0);
		assert.match(result.stderr, /No matching distribution|Could not find a version/);
	} finally {
		await rm(f.temporary, { recursive: true, force: true });
	}
});
