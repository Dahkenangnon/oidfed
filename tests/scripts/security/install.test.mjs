/** Verify binary checksums and allowlisted archive extraction. */

import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, readFile, rm, access } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { installBinary, tools } from "../../../scripts/security/install.mjs";

test("ShellCheck installation verifies hashes and extracts only its nested executable", async (t) => {
	const temporary = await mkdtemp(join(tmpdir(), "oidfed-binary-installer-"));
	try {
		const source = join(temporary, "shellcheck-v0.11.0");
		await mkdir(source);
		await writeFile(join(source, "shellcheck"), "#!/bin/sh\nprintf 'fixture shellcheck\\n'\n");
		await writeFile(join(source, "unrelated"), "must not be installed");
		const archive = join(temporary, "fixture.tar.gz");
		const packed = spawnSync("tar", ["czf", archive, "-C", temporary, "shellcheck-v0.11.0"]);
		assert.equal(packed.status, 0, packed.stderr.toString());
		const data = await readFile(archive);
		t.mock.method(globalThis, "fetch", async () => new Response(data));
		const realTar = spawnSync("sh", ["-c", "command -v tar"], { encoding: "utf8" }).stdout.trim();
		const wrappers = join(temporary, "tools");
		await mkdir(wrappers);
		const calls = join(temporary, "tar-calls.jsonl");
		await writeFile(
			join(wrappers, "tar"),
			`#!${process.execPath}\nconst fs=require("node:fs"); const cp=require("node:child_process"); const args=process.argv.slice(2); fs.appendFileSync(${JSON.stringify(calls)},JSON.stringify(args)+"\\n"); const result=cp.spawnSync(${JSON.stringify(realTar)},args,{stdio:"inherit"}); process.exit(result.status??1);`,
			{ mode: 0o755 },
		);
		const previousPath = process.env.PATH;
		process.env.PATH = `${wrappers}:${previousPath}`;
		t.after(() => {
			process.env.PATH = previousPath;
		});
		const tool = { ...tools.shellcheck, sha256: createHash("sha256").update(data).digest("hex") };
		const destination = join(temporary, "bin");
		await installBinary("shellcheck", tool, destination);
		const result = spawnSync(join(destination, "shellcheck"), [], { encoding: "utf8" });
		assert.equal(result.status, 0, result.stderr);
		assert.equal(result.stdout, "fixture shellcheck\n");
		const extractions = (await readFile(calls, "utf8"))
			.trim()
			.split("\n")
			.map((line) => JSON.parse(line))
			.filter((args) => args[0] === "xzf");
		assert.equal(extractions.length, 1);
		assert.deepEqual(
			extractions[0].slice(-2),
			["--", tools.shellcheck.member],
			"extract only the allowlisted member, not the whole archive",
		);
		await assert.rejects(access(join(destination, "unrelated")));
		await assert.rejects(
			installBinary("shellcheck", { ...tool, sha256: "0".repeat(64) }, destination),
			/checksum mismatch/,
		);
		await assert.rejects(
			installBinary("shellcheck", { ...tool, member: "shellcheck-v0.11.0/missing" }, destination),
			/missing from its archive/,
		);
		assert.equal(
			(await readFile(join(destination, "shellcheck"), "utf8")).includes("fixture shellcheck"),
			true,
			"failed updates preserve the installed executable",
		);
	} finally {
		await rm(temporary, { recursive: true, force: true });
	}
});
