import assert from "node:assert/strict";
import { test } from "node:test";
import { documentation, renderDocumentation } from "../app/lib/docs.server";
import { docsPackage, docsSeo, SECTION_SEPARATOR } from "../app/lib/docs-meta";
import { SITE_NAME } from "../app/lib/seo";

/** Every documentation route, with the SEO text the route module derives for it. */
const pages = [...documentation.keys()].flatMap((path) => {
	const page = renderDocumentation(path);
	if (!page) return [];
	return [{ path, ...docsSeo({ heading: page.title, description: page.description, path }) }];
});

test("the package segment is read from API paths only", () => {
	assert.equal(docsPackage("/docs/api/core"), "core");
	assert.equal(docsPackage("/docs/api/core/marks"), "core");
	assert.equal(docsPackage("/docs/api"), undefined);
	assert.equal(docsPackage("/docs/features/1.1.entity-roles"), undefined);
	assert.equal(docsPackage("/docs/api/corelike"), undefined);
});

test("a package index reads as a reference, not as an npm identifier", () => {
	const { title } = docsSeo({
		heading: "@oidfed/core API",
		description: "Every entry below is exported from @oidfed/core.",
		path: "/docs/api/core",
	});
	assert.equal(title, "Core API reference");
});

test("an API page carries its package as a short section, not as a scope", () => {
	const { title } = docsSeo({
		heading: "Trust Marks",
		description: "Establish issuer trust before relying on a mark.",
		path: "/docs/api/core/marks",
	});
	assert.equal(title, "Trust Marks · Core API");
});

test("pages that share a heading across packages get distinct titles", () => {
	const input = { heading: "Federation hosts", description: "Construct one host." };
	assert.notEqual(
		docsSeo({ ...input, path: "/docs/api/authority/hosts" }).title,
		docsSeo({ ...input, path: "/docs/api/leaf/hosts" }).title,
	);
});

test("a guide drops its manual section number", () => {
	const { title } = docsSeo({
		heading: "16.9. Apply effective DCQL and framework query policy",
		description: "Maya presents a credential.",
		path: "/docs/features/16.9.wallet-dcql",
	});
	assert.equal(title, "Apply effective DCQL and framework query policy");
});

test("a TypeScript example is titled and described as an example", () => {
	const { title, description } = docsSeo({
		heading: "software-crypto.ts",
		description: "OpenID Federation guides and public JavaScript and TypeScript API reference.",
		path: "/docs/examples/software-crypto",
	});
	assert.equal(title, "Software crypto example");
	assert.match(description, /TypeScript example/);
});

test("the index pages carry the subject a search listing needs", () => {
	const index = (path: string) =>
		docsSeo({ heading: "Documentation", description: "d", path }).title;
	for (const path of ["/docs", "/docs/api", "/docs/features"]) {
		assert.match(index(path), /OpenID Federation/, path);
	}
});

test("breadcrumbs trail only through pages that exist", () => {
	assert.deepEqual(docsSeo({ heading: "Trust Marks", description: "d", path: "/docs/api/core/marks" }).breadcrumbs, [
		{ name: "Documentation", path: "/docs" },
		{ name: "API reference", path: "/docs/api" },
		{ name: "Core API", path: "/docs/api/core" },
		{ name: "Trust Marks", path: "/docs/api/core/marks" },
	]);
	for (const { path, breadcrumbs } of pages) {
		assert.equal(breadcrumbs.at(-1)?.path, path);
		for (const crumb of breadcrumbs) {
			assert.ok(documentation.has(crumb.path), `${path} trails through missing ${crumb.path}`);
		}
	}
});

test("no title repeats a segment or spells the brand itself", () => {
	for (const { path, title } of pages) {
		const segments = title.split(" · ");
		assert.equal(new Set(segments).size, segments.length, `${path} repeats a title segment`);
		assert.doesNotMatch(title, /@oidfed/, `${path} names an npm scope in its title`);
		assert.doesNotMatch(
			title,
			new RegExp(`[|${SECTION_SEPARATOR.trim()}]\\s*${SITE_NAME}$`, "i"),
			`${path} spells the brand suffix itself`,
		);
		assert.doesNotMatch(title, /^\d/, `${path} opens with a section number`);
	}
});

test("every title and description stays inside a search listing", () => {
	const long = pages.filter(({ title }) => `${title} | ${SITE_NAME}`.length > 70);
	assert.deepEqual(long.map(({ path }) => path), []);
	for (const { path, description } of pages) {
		assert.ok(description.length >= 70, `${path} description is only ${description.length} chars`);
		assert.ok(description.length <= 160, `${path} description is ${description.length} chars`);
	}
});

test("every documentation title is unique", () => {
	const seen = new Map<string, string>();
	for (const { path, title } of pages) {
		const clash = seen.get(title);
		assert.equal(clash, undefined, `${path} and ${clash} share the title "${title}"`);
		seen.set(title, path);
	}
});
