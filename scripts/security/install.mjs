/** Install pinned security tools in the workspace's ignored tool cache. */

import { createHash } from "node:crypto";
import { mkdir, mkdtemp, writeFile, chmod, rm, copyFile, access } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { root } from "./scope.mjs";

export const tools = Object.freeze({
	"osv-scanner": {
		version: "2.7.1",
		repository: "google/osv-scanner",
		asset: "osv-scanner_linux_amd64",
		sha256: "fb7dab19a8bd9bbe5c3189f09d4b7ee1820c9553a23bac202648a56efd2f6ee8",
	},
	gitleaks: {
		version: "8.30.1",
		repository: "gitleaks/gitleaks",
		asset: "gitleaks_8.30.1_linux_x64.tar.gz",
		sha256: "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
	},
	zizmor: {
		version: "1.32.0",
		repository: "zizmorcore/zizmor",
		asset: "zizmor-x86_64-unknown-linux-gnu.tar.gz",
		sha256: "bb110cc765eca9cd7efb2e284a956be5974c60027b0970f16397d86208a9957b",
	},
	actionlint: {
		version: "1.7.12",
		repository: "rhysd/actionlint",
		asset: "actionlint_1.7.12_linux_amd64.tar.gz",
		sha256: "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8",
	},
});
export const bin = join(root, "node_modules/.cache/spec-security/bin");
export const semgrepEnvironment = join(root, "node_modules/.cache/spec-security/semgrep");
export const semgrepBin = join(semgrepEnvironment, "bin");
const SEMGREP_VERSION = "1.185.0";

/** Resolve only the reviewed interpreter-specific dependency locks. */
export function semgrepRequirements(version) {
	if (!["3.12", "3.13", "3.14"].includes(version))
		throw new Error(`Semgrep installation requires Python 3.12–3.14; found ${version}`);
	return join(root, "scripts/security/requirements", `semgrep-py${version.replace(".", "")}.txt`);
}

/** Replace the generated environment so previously unlocked packages cannot satisfy installation. */
export async function installSemgrep(python = "python3", directory = semgrepEnvironment) {
	const version = execFileSync(
		python,
		["-c", "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"],
		{ encoding: "utf8" },
	).trim();
	const requirements = semgrepRequirements(version);
	await access(requirements);
	console.log(`Installing Semgrep ${SEMGREP_VERSION} with the Python ${version} hash lock`);
	execFileSync(python, ["-m", "venv", "--clear", directory], { stdio: "inherit" });
	const interpreter = join(directory, "bin/python");
	execFileSync(
		interpreter,
		[
			"-m",
			"pip",
			"install",
			"--disable-pip-version-check",
			"--require-hashes",
			"--only-binary=:all:",
			"-r",
			requirements,
		],
		{ stdio: "inherit" },
	);
	execFileSync(interpreter, ["-m", "pip", "check"], { stdio: "inherit" });
	const installed = execFileSync(join(directory, "bin/semgrep"), ["--version"], {
		encoding: "utf8",
		env: {
			...process.env,
			SEMGREP_SEND_METRICS: "off",
			SEMGREP_ENABLE_VERSION_CHECK: "0",
			SEMGREP_SETTINGS_FILE: join(directory, "settings.yml"),
			SEMGREP_LOG_FILE: join(directory, "semgrep.log"),
		},
	}).trim();
	if (installed !== SEMGREP_VERSION) throw new Error(`Unexpected Semgrep version: ${installed}`);
	console.log(`Installed Semgrep ${installed} from verified wheels`);
}

async function install() {
	if (process.platform !== "linux" || process.arch !== "x64")
		throw new Error(
			"Automatic scanner installation supports Linux x64; install the documented versions on this platform.",
		);
	await mkdir(bin, { recursive: true });
	const temporary = await mkdtemp(join(tmpdir(), "oidfed-scanners-"));
	try {
		for (const [name, tool] of Object.entries(tools)) {
			console.log(`Installing ${name} ${tool.version}`);
			const response = await fetch(
				`https://github.com/${tool.repository}/releases/download/v${tool.version}/${tool.asset}`,
				{ signal: AbortSignal.timeout(600_000) },
			);
			if (!response.ok) throw new Error(`${name} download failed: HTTP ${response.status}`);
			const data = Buffer.from(await response.arrayBuffer());
			if (createHash("sha256").update(data).digest("hex") !== tool.sha256)
				throw new Error(`${name} checksum mismatch`);
			const archive = join(temporary, tool.asset);
			await writeFile(archive, data);
			if (tool.asset.endsWith(".tar.gz")) {
				const members = execFileSync("tar", ["tzf", archive], { encoding: "utf8" })
					.trim()
					.split("\n");
				const member = members.find((path) => path === name || path === `./${name}`);
				if (!member) throw new Error(`${name} is missing from its archive`);
				execFileSync("tar", ["xzf", archive, "-C", temporary, "--", member]);
				await copyFile(join(temporary, name), join(bin, name));
			} else await copyFile(archive, join(bin, name));
			await chmod(join(bin, name), 0o755);
			console.log(`Installed ${name} ${tool.version} (SHA-256 verified)`);
		}
		try {
			await installSemgrep();
		} catch (cause) {
			throw new Error(
				"Semgrep setup failed. Use Python 3.12–3.14 with venv and pip, then rerun pnpm security:install; unlocked packages and source builds are not allowed.",
				{ cause },
			);
		}
	} finally {
		await rm(temporary, { recursive: true, force: true });
	}
}

if (process.argv[1] === fileURLToPath(import.meta.url)) await install();
