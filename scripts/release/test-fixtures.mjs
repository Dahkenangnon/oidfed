/** Offline archives and registry state for exercising release transactions. */
import { gzipSync } from "node:zlib";
import { readFileSync, writeFileSync } from "node:fs";
import { join, basename } from "node:path";
import { TARGETS } from "./catalog.mjs";
import { requiredPackedEntries } from "../check-pack-manifests.mjs";
import { createArtifacts } from "./artifacts.mjs";
export const SHA = "a".repeat(40);
export function archive(entries) {
	const chunks = [];
	for (const [name, text, type = 48] of entries) {
		const bytes = Buffer.from(text),
			header = Buffer.alloc(512);
		header.write(name, 0, 100);
		header.write("0000755\0", 100, 8);
		header.write("0000000\0", 108, 8);
		header.write("0000000\0", 116, 8);
		header.write(bytes.length.toString(8).padStart(11, "0") + "\0", 124, 12);
		header.fill(32, 148, 156);
		header[156] = type;
		const sum = header.reduce((a, b) => a + b, 0);
		header.write(sum.toString(8).padStart(6, "0") + "\0 ", 148, 8);
		chunks.push(header, bytes, Buffer.alloc((512 - (bytes.length % 512)) % 512));
	}
	chunks.push(Buffer.alloc(1024));
	return gzipSync(Buffer.concat(chunks));
}
export function bundle(directory, scope = "all") {
	return createArtifacts({
		directory,
		scope,
		sourceSha: SHA,
		workflowSha: SHA,
		runId: "123",
		notes: (p) => `Notes for ${p.name}.\n`,
		execute(command, args) {
			if (command !== "pnpm" || args[0] !== "--dir") throw Error("wrong pack command");
			const target = TARGETS.find(
				(p) => basename(args[1]) === p.scope || (p.scope === "cli" && basename(args[1]) === "cli"),
			);
			if (!target || !args[1].endsWith(target.dir)) throw Error("wrong source package");
			const pkg = JSON.parse(readFileSync(`${target.dir}/package.json`, "utf8"));
			for (const bucket of [
				"dependencies",
				"devDependencies",
				"peerDependencies",
				"optionalDependencies",
			])
				for (const [name, value] of Object.entries(pkg[bucket] ?? {}))
					if (name.startsWith("@oidfed/") && value.startsWith("workspace:")) {
						const dependency = TARGETS.find((p) => p.name === name);
						pkg[bucket][name] =
							"^" + JSON.parse(readFileSync(`${dependency.dir}/package.json`, "utf8")).version;
					}
			const entries = requiredPackedEntries(target).map((name) => [
				name,
				name === "package/package.json" ? JSON.stringify(pkg) : "fixture",
			]);
			writeFileSync(
				join(args[args.indexOf("--pack-destination") + 1], `${target.scope}.tgz`),
				archive(entries),
			);
		},
	});
}
export function registry() {
	const data = new Map();
	return {
		data,
		read: async (path) => data.get(path),
		put(record) {
			data.set(`${encodeURIComponent(record.name)}/${record.version}`, {
				name: record.name,
				version: record.version,
				dist: { integrity: record.integrity },
			});
		},
	};
}
