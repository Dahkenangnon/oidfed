import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { buildMeta, SITE_NAME } from "../app/lib/seo";

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
