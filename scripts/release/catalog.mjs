/** The package identities and toolchain shared by release preparation and publication. */

import semver from "semver";

export const REPOSITORY = "Dahkenangnon/oidfed";
export const WORKFLOW = ".github/workflows/release.yml";
export const NPM_VERSION = "11.21.2";
export const TARGETS = Object.freeze(
	[
		{ scope: "core", name: "@oidfed/core", dir: "packages/core", kind: "library" },
		{ scope: "authority", name: "@oidfed/authority", dir: "packages/authority", kind: "library" },
		{ scope: "leaf", name: "@oidfed/leaf", dir: "packages/leaf", kind: "library" },
		{ scope: "oidc", name: "@oidfed/oidc", dir: "packages/oidc", kind: "library" },
		{ scope: "wallet", name: "@oidfed/wallet", dir: "packages/wallet", kind: "library" },
		{ scope: "cli", name: "@oidfed/cli", dir: "tools/cli", kind: "cli" },
		{ scope: "crypto", name: "@oidfed/crypto", dir: "packages/crypto", kind: "library" },
	].map(Object.freeze),
);

export function getTargets(scope = "all") {
	if (scope === "all") return TARGETS;
	const target = TARGETS.find((item) => item.scope === scope);
	if (!target)
		throw new Error(
			`Unknown scope "${scope}". Expected all or ${TARGETS.map((p) => p.scope).join(", ")}`,
		);
	return [target];
}

export function version(value) {
	if (typeof value !== "string" || semver.valid(value) !== value)
		throw new Error(`Invalid release version: ${String(value)}`);
	return value;
}

export function parseTag(tag) {
	const match = typeof tag === "string" && tag.match(/^([^/]+)\/v(.+)$/);
	if (!match || match[1] === "all") throw new Error("Use a package-specific release tag");
	return { ...getTargets(match[1])[0], version: version(match[2]), tag };
}

export function distributionTag(value) {
	return semver.prerelease(version(value)) ? "next" : "latest";
}

/** Sort selected packages by the internal dependencies in their packed manifests. */
export function publicationOrder(records) {
	const byName = new Map(records.map((record) => [record.name, record]));
	if (byName.size !== records.length) throw new Error("Duplicate release packages");
	const active = new Set();
	const completed = new Set();
	const ordered = [];
	function visit(record) {
		if (completed.has(record.name)) return;
		if (active.has(record.name)) throw new Error("Cyclic release dependencies");
		active.add(record.name);
		for (const [name, range] of Object.entries(record.dependencies ?? {})) {
			const dependency = byName.get(name);
			if (dependency) {
				if (!semver.satisfies(dependency.version, range))
					throw new Error(`${record.name} requires ${name}@${range}`);
				visit(dependency);
			}
		}
		active.delete(record.name);
		completed.add(record.name);
		ordered.push(record);
	}
	for (const record of records) visit(record);
	return ordered;
}
