import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import { extractFences, extractQuickstartExamples } from "../../scripts/check-doc-snippets.mjs";

const QUICKSTART = [
	"export const quickstartExamples = [",
	"\t{",
	'\t\tid: "anchor",',
	'\t\tfilename: "trust-anchor.ts",',
	'\t\tcode: `import { TrustAnchor } from "@oidfed/authority";',
	"",
	"export async function createAnchor() {",
	// biome-ignore lint/suspicious/noTemplateCurlyInString: the fixture mirrors escaped source text
	"  const entityId = \\`\\${base}/anchor\\`;",
	"  return TrustAnchor.create({ entityId });",
	"}`,",
	"\t},",
	"\t{",
	'\t\tid: "leaf",',
	'\t\tfilename: "leaf.ts",',
	'\t\tcode: `const leaf = "leaf";`,',
	"\t},",
	"];",
].join("\n");

describe("extractQuickstartExamples", () => {
	it("recovers one snippet per example, keyed by id", () => {
		const examples = extractQuickstartExamples(QUICKSTART);
		assert.deepEqual(
			examples.map(({ id }) => id),
			["anchor", "leaf"],
		);
	});

	it("unescapes the template literal back into compilable TypeScript", () => {
		const [anchor] = extractQuickstartExamples(QUICKSTART);
		assert.ok(anchor);
		assert.ok(
			// biome-ignore lint/suspicious/noTemplateCurlyInString: asserting on literal source text
			anchor.code.includes("const entityId = `${base}/anchor`;"),
			`escaped interpolation survived: ${anchor.code}`,
		);
		assert.ok(anchor.code.includes('import { TrustAnchor } from "@oidfed/authority";'));
		assert.doesNotMatch(anchor.code, /\\`/, "backticks must be unescaped");
	});

	it("reports nothing for a source that declares no examples", () => {
		assert.deepEqual(extractQuickstartExamples("export const other = [];"), []);
	});
});

describe("extractFences", () => {
	it("collects only TypeScript fences, numbered by position", () => {
		const markdown = [
			"# Guide",
			"",
			"```ts",
			"const a: number = 1;",
			"```",
			"",
			"```bash",
			"npm install",
			"```",
			"",
			"```typescript",
			"const b: string = 'x';",
			"```",
		].join("\n");
		const fences = extractFences(markdown, "guide.md");
		assert.deepEqual(
			fences.map(({ code }) => code.trim()),
			["const a: number = 1;", "const b: string = 'x';"],
		);
		assert.deepEqual(
			fences.map(({ id }) => id),
			["guide.md:3", "guide.md:11"],
		);
	});

	it("skips fences marked as not compilable", () => {
		const markdown = ["```ts no-check", "this is not typescript", "```"].join("\n");
		assert.deepEqual(extractFences(markdown, "guide.md"), []);
	});

	it("reports nothing for prose", () => {
		assert.deepEqual(extractFences("Just a paragraph.\n", "guide.md"), []);
	});
});
