#!/usr/bin/env node
/**
 * Documentation guard: typecheck the TypeScript the project publishes as
 * copy-paste examples.
 *
 * The home page carries its quickstart snippets as template literals inside
 * `apps/home/app/components/quickstart.tsx`, and the guides carry theirs in
 * fenced blocks. Neither form is visible to `tsc`, so a published example can
 * drift from the API it demonstrates — a missing `await`, a renamed option, a
 * version pin for a major that was never released — without any check failing.
 * This script extracts every snippet, writes it to a scratch project wired to
 * the built package types, and runs `tsc --noEmit` over the set.
 *
 * Requires the workspace packages to be built, because it checks the published
 * surface (`dist/index.d.ts`) rather than the source: run `pnpm build` first.
 *
 * Exit codes:
 *   0  every snippet compiles
 *   1  at least one snippet fails to compile (details on stderr)
 *   2  invalid invocation, unreadable sources, or the packages are not built
 *
 * Usage:
 *   node scripts/check-doc-snippets.mjs
 */

import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** Packages whose published types the snippets are checked against. */
const PACKAGES = ["core", "crypto", "authority", "leaf", "oidc", "wallet"];

/** Published subpath exports the snippets import directly. */
const PACKAGE_SUBPATHS = ["crypto/web", "crypto/jose"];

const QUICKSTART_SOURCE = "apps/home/app/components/quickstart.tsx";

/**
 * Markdown whose TypeScript fences are written to stand on their own, so each
 * one compiles as a module in isolation.
 *
 * `docs/` is deliberately absent. Its guides narrate one scenario across
 * several fences that share earlier bindings, and some import packages the
 * repository does not depend on, so a per-fence check reports hundreds of
 * missing names rather than real drift. Including them needs per-page
 * concatenation and resolution for their external imports; until then this
 * guard covers the snippets a reader is invited to copy whole.
 */
const MARKDOWN_SOURCES = [
	"README.md",
	"packages/core/README.md",
	"packages/crypto/README.md",
	"packages/authority/README.md",
	"packages/leaf/README.md",
	"packages/oidc/README.md",
	"packages/wallet/README.md",
];

/**
 * Fence infostrings that opt a block out of the check. `signature` and
 * `fragment` blocks quote a declaration out of context and never stood alone.
 */
const SKIP_FENCE = /\b(signature|fragment|no-check|nocheck|pseudo|ignore)\b/;

/**
 * Pull the quickstart examples out of the home page component.
 * Pure: takes the component source, returns `{ id, code }` for each example in
 * declaration order. The `code` field is the template literal with its escapes
 * resolved, so it is valid TypeScript again.
 */
export function extractQuickstartExamples(source) {
	const examples = [];
	const ids = [...source.matchAll(/^\t\tid: "([^"]+)",$/gm)].map(([, id]) => id);
	const bodies = [...source.matchAll(/^\t\tcode: `((?:[^`\\]|\\[\s\S])*)`,$/gm)].map(([, body]) =>
		body.replace(/\\`/g, "`").replace(/\\\$/g, "$").replace(/\\\\/g, "\\"),
	);
	for (const [index, code] of bodies.entries()) {
		examples.push({ id: ids[index] ?? `example-${index + 1}`, code });
	}
	return examples;
}

/**
 * Pull fenced TypeScript out of a markdown document.
 * Pure: takes the markdown and the path it came from, returns `{ id, code }`
 * per block, where `id` is `<path>:<1-indexed line of the opening fence>`.
 */
export function extractFences(markdown, displayPath) {
	const fences = [];
	const lines = markdown.split("\n");
	let opened = -1;
	let info = "";
	let body = [];
	for (const [index, line] of lines.entries()) {
		const fence = /^```(.*)$/.exec(line);
		if (!fence) {
			if (opened >= 0) body.push(line);
			continue;
		}
		if (opened < 0) {
			opened = index;
			info = (fence[1] ?? "").trim();
			body = [];
			continue;
		}
		const language = info.split(/\s+/)[0] ?? "";
		if ((language === "ts" || language === "typescript") && !SKIP_FENCE.test(info)) {
			fences.push({ id: `${displayPath}:${opened + 1}`, code: body.join("\n") });
		}
		opened = -1;
		info = "";
		body = [];
	}
	return fences;
}

/** Verify the package types the snippets import actually exist. */
function missingPackageTypes() {
	return PACKAGES.filter((name) => !existsSync(resolve(ROOT, `packages/${name}/dist/index.d.ts`)));
}

/** Collect every snippet the project publishes, newest convention first. */
function collectSnippets() {
	const snippets = [];
	const quickstart = resolve(ROOT, QUICKSTART_SOURCE);
	if (!existsSync(quickstart)) {
		throw new Error(`Missing ${QUICKSTART_SOURCE}`);
	}
	for (const { id, code } of extractQuickstartExamples(readFileSync(quickstart, "utf8"))) {
		snippets.push({ id: `${QUICKSTART_SOURCE}#${id}`, code });
	}
	for (const file of MARKDOWN_SOURCES) {
		const abs = resolve(ROOT, file);
		if (!existsSync(abs)) {
			throw new Error(`Missing snippet source: ${file}`);
		}
		snippets.push(...extractFences(readFileSync(abs, "utf8"), file));
	}
	return snippets;
}

/** A filesystem-safe, collision-free name for each snippet. */
function fileNameFor(id, taken) {
	const slug = id.replace(/[^a-zA-Z0-9]+/g, "-").replace(/^-|-$/g, "") || "snippet";
	let name = slug;
	for (let suffix = 2; taken.has(name); suffix += 1) name = `${slug}-${suffix}`;
	taken.add(name);
	return name;
}

/** Write the snippets to a scratch project and return its directory. */
function stageProject(snippets) {
	const dir = mkdtempSync(join(tmpdir(), "oidfed-doc-snippets-"));
	mkdirSync(join(dir, "src"));
	const taken = new Set();
	for (const { id, code } of snippets) {
		writeFileSync(join(dir, "src", `${fileNameFor(id, taken)}.ts`), `${code}\n`);
	}
	const paths = Object.fromEntries([
		...PACKAGES.map((name) => [
			`@oidfed/${name}`,
			[resolve(ROOT, `packages/${name}/dist/index.d.ts`)],
		]),
		...PACKAGE_SUBPATHS.map((subpath) => [
			`@oidfed/${subpath}`,
			[resolve(ROOT, `packages/${subpath.replace("/", "/dist/")}.d.ts`)],
		]),
	]);
	// Staged as ESM so a snippet may use top-level await, as the guides do.
	writeFileSync(join(dir, "package.json"), `${JSON.stringify({ type: "module" }, null, 2)}\n`);
	writeFileSync(
		join(dir, "tsconfig.json"),
		`${JSON.stringify(
			{
				compilerOptions: {
					target: "ES2022",
					module: "NodeNext",
					moduleResolution: "NodeNext",
					strict: true,
					exactOptionalPropertyTypes: true,
					noEmit: true,
					skipLibCheck: true,
					ignoreDeprecations: "6.0",
					lib: ["ES2022", "DOM"],
					baseUrl: ".",
					paths,
				},
				include: ["src"],
			},
			null,
			2,
		)}\n`,
	);
	return dir;
}

function main() {
	const unbuilt = missingPackageTypes();
	if (unbuilt.length > 0) {
		process.stderr.write(
			`doc-snippets check cannot run: no built types for ${unbuilt
				.map((name) => `@oidfed/${name}`)
				.join(", ")}. Run \`pnpm build\` first.\n`,
		);
		process.exit(2);
	}

	let snippets;
	try {
		snippets = collectSnippets();
	} catch (err) {
		process.stderr.write(`${err.message}\n`);
		process.exit(2);
	}

	if (snippets.length === 0) {
		process.stderr.write(
			"doc-snippets check found no snippets to check — is the extractor stale?\n",
		);
		process.exit(2);
	}

	const tsc = resolve(ROOT, "node_modules/.bin/tsc");
	if (!existsSync(tsc)) {
		process.stderr.write("doc-snippets check cannot run: typescript is not installed.\n");
		process.exit(2);
	}

	const dir = stageProject(snippets);
	const result = spawnSync(tsc, ["-p", join(dir, "tsconfig.json")], { encoding: "utf8" });

	if (result.error) {
		rmSync(dir, { recursive: true, force: true });
		process.stderr.write(`doc-snippets check could not run tsc: ${result.error.message}\n`);
		process.exit(2);
	}
	if (result.status === 0) {
		rmSync(dir, { recursive: true, force: true });
		process.stdout.write(`doc-snippets check OK: ${snippets.length} published snippets compile\n`);
		process.exit(0);
	}

	// Left on disk: the paths in the tsc output have to stay resolvable.
	process.stderr.write("doc-snippets check FAILED:\n");
	process.stderr.write(`${(result.stdout || result.stderr).trim()}\n`);
	process.stderr.write(`\nSnippets were staged in ${dir} (kept for inspection).\n`);
	process.exit(1);
}

const entry = process.argv[1];
if (entry !== undefined && import.meta.url === pathToFileURL(entry).href) main();
