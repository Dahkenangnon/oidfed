/** Install pinned security tools in the workspace's ignored tool cache. */

import { createHash } from "node:crypto";
import { mkdir, mkdtemp, writeFile, chmod, rm, copyFile } from "node:fs/promises";
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
	shellcheck: {
		version: "0.11.0",
		repository: "koalaman/shellcheck",
		asset: "shellcheck-v0.11.0.linux.x86_64.tar.gz",
		member: "shellcheck-v0.11.0/shellcheck",
		sha256: "b7af85e41cc99489dcc21d66c6d5f3685138f06d34651e6d34b42ec6d54fe6f6",
	},
});
export const bin = join(root, "node_modules/.cache/spec-security/bin");
/** Install one checksum-verified executable, extracting only its allowlisted archive member. */
export async function installBinary(name, tool, destination = bin) {
	await mkdir(destination, { recursive: true });
	const temporary = await mkdtemp(join(tmpdir(), "oidfed-scanners-"));
	try {
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
			const expected = tool.member ?? name;
			const member = members.find((path) => path === expected || path === `./${expected}`);
			if (!member) throw new Error(`${name} is missing from its archive`);
			execFileSync("tar", ["xzf", archive, "-C", temporary, "--", member]);
			await copyFile(join(temporary, expected), join(destination, name));
		} else await copyFile(archive, join(destination, name));
		await chmod(join(destination, name), 0o755);
		console.log(`Installed ${name} ${tool.version} (SHA-256 verified)`);
	} finally {
		await rm(temporary, { recursive: true, force: true });
	}
}

async function install() {
	if (process.platform !== "linux" || process.arch !== "x64")
		throw new Error(
			"Automatic scanner installation supports Linux x64; install the documented versions on this platform.",
		);
	for (const [name, tool] of Object.entries(tools)) await installBinary(name, tool);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) await install();
