import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { buildMeta, HOME_DESCRIPTION, SITE_NAME } from "../app/lib/seo";

type Tags = ReturnType<typeof buildMeta>;

function documentTitle(tags: Tags): string | undefined {
	const tag = tags.find((item) => "title" in item);
	return tag && "title" in tag ? tag.title : undefined;
}

function property(tags: Tags, name: string): string | undefined {
	const tag = tags.find((item) => "property" in item && item.property === name);
	return tag && "property" in tag ? tag.content : undefined;
}

function named(tags: Tags, name: string): string | undefined {
	const tag = tags.find((item) => "name" in item && item.name === name);
	return tag && "name" in tag ? tag.content : undefined;
}

const INPUT = { title: "About the project", description: "A description.", path: "/about" };

test("every page title ends with the site name", () => {
	assert.equal(documentTitle(buildMeta(INPUT)), `About the project | ${SITE_NAME}`);
});

test("a title that already carries the site name is not suffixed twice", () => {
	const tags = buildMeta({ ...INPUT, title: `About the project | ${SITE_NAME}` });
	assert.equal(documentTitle(tags), `About the project | ${SITE_NAME}`);
});

test("the social titles match the document title", () => {
	const tags = buildMeta(INPUT);
	const expected = `About the project | ${SITE_NAME}`;
	assert.equal(property(tags, "og:title"), expected);
	assert.equal(named(tags, "twitter:title"), expected);
});

test("route titles leave the brand suffix to buildMeta", () => {
	const routes = join(import.meta.dirname, "..", "app", "routes");
	for (const file of readdirSync(routes).filter((name) => name.endsWith(".tsx"))) {
		const source = readFileSync(join(routes, file), "utf8");
		for (const [, title] of source.matchAll(/title:\s*"([^"]+)"/g)) {
			assert.doesNotMatch(
				title ?? "",
				/[|—]\s*@?oidfed/i,
				`${file} spells its own brand suffix in "${title}" — pass a bare title instead`,
			);
		}
	}
});

/** Descriptions a route shares through `seo.ts` instead of spelling inline. */
const SHARED_DESCRIPTIONS: Record<string, string> = { HOME_DESCRIPTION };

/** The `meta()` body of each route, where the page-level SEO text is declared. */
function metaBodies(): { file: string; body: string }[] {
	const routes = join(import.meta.dirname, "..", "app", "routes");
	return readdirSync(routes)
		.filter((name) => name.endsWith(".tsx"))
		.flatMap((file) => {
			const source = readFileSync(join(routes, file), "utf8");
			const start = source.indexOf("export function meta(");
			if (start < 0) return [];
			const end = source.indexOf("\n}", start);
			return [{ file, body: source.slice(start, end) }];
		});
}

test("every route title fits a search listing once the brand is appended", () => {
	for (const { file, body } of metaBodies()) {
		for (const [, title] of body.matchAll(/title:\s*"([^"]+)"/g)) {
			const rendered = `${title} | ${SITE_NAME}`;
			assert.ok(rendered.length <= 70, `${file}: "${rendered}" is ${rendered.length} chars`);
		}
	}
});

test("every route description fills a search snippet without overflowing it", () => {
	for (const { file, body } of metaBodies()) {
		const match = /description:\s*\n?\s*(?:"((?:[^"\\]|\\.)+)"|([A-Z][A-Z_]+))/.exec(body);
		const named = match?.[2];
		const description = match?.[1] ?? (named ? SHARED_DESCRIPTIONS[named] : undefined);
		assert.ok(description, `${file} declares no resolvable description`);
		assert.ok(description.length >= 70, `${file}: description is ${description.length} chars`);
		assert.ok(description.length <= 160, `${file}: description is ${description.length} chars`);
	}
});
