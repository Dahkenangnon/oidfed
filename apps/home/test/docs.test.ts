import assert from "node:assert/strict";
import { test } from "node:test";
import {
	documentation,
	guideCatalog,
	renderDocumentation,
	renderMarkdown,
} from "../app/lib/docs.server";

test("the documentation routes cover all package indexes and TypeScript helpers", () => {
	for (const name of ["authority", "core", "crypto", "leaf", "oidc", "wallet"]) {
		assert.equal(documentation.get(`/docs/api/${name}`), `api/${name}/README.md`);
		assert.ok(renderDocumentation(`/docs/api/${name}`)?.title);
	}
	assert.match(
		renderDocumentation("/docs/examples/software-crypto")?.html ?? "",
		/class="language-ts"/,
	);
	assert.equal(renderDocumentation("/docs/../package"), undefined);
});

test("markdown generates local routes, stable anchors, and GitHub links for other source files", () => {
	const page = renderMarkdown(
		"api/core/README.md",
		[
			"# Core",
			"",
			"## `createTrustAnchorSet()`",
			"",
			"## `createTrustAnchorSet()`",
			"",
			"[Storage](storage.md#federationstorage) and [contributing](../../../CONTRIBUTING.md).",
		].join("\n"),
	);
	assert.deepEqual(
		page.headings.map(({ id }) => id),
		["createtrustanchorset", "createtrustanchorset-1"],
	);
	assert.match(page.html, /href="\/docs\/api\/core\/storage#federationstorage"/);
	assert.match(
		page.html,
		/href="https:\/\/github.com\/Dahkenangnon\/oidfed\/blob\/main\/CONTRIBUTING.md"/,
	);
});

test("only plain details and summary tags survive markdown HTML rendering", () => {
	const page = renderMarkdown(
		"README.md",
		[
			"# Docs",
			"",
			"<details>",
			"<summary>Example</summary>",
			"",
			"**Rendered Markdown** with <aside>escaped HTML</aside>.",
			"",
			"</details>",
			"",
			'<details title="custom">Unsupported attributes</details>',
		].join("\n"),
	);
	assert.match(page.html, /<details><summary>Example<\/summary>/);
	assert.match(page.html, /<strong>Rendered Markdown<\/strong>/);
	assert.match(page.html, /&lt;aside&gt;escaped HTML&lt;\/aside&gt;/);
	assert.doesNotMatch(page.html, /<details title=/);
});

test("the sidebar includes every numbered feature guide in numeric order", () => {
	const links = guideCatalog.flatMap(({ path, guides }) => [
		path,
		...guides.map((guide) => guide.path),
	]);
	assert.deepEqual(
		links.sort(),
		[...documentation.keys()].filter((path) => path.startsWith("/docs/features/")).sort(),
	);
	const marks = guideCatalog.find(({ path }) => path === "/docs/features/6.trust-marks");
	assert.ok(marks);
	assert.match(marks.guides[1]?.path ?? "", /\/6\.2\./);
	assert.match(marks.guides[9]?.path ?? "", /\/6\.10\./);
});

test("known fences receive light and dark tokens and unknown fences remain escaped text", () => {
	const page = renderMarkdown(
		"README.md",
		[
			"# Docs",
			"",
			"```typescript signature",
			'const name = "<tag>";',
			"```",
			"",
			"```unrecognized",
			"<tag>",
			"```",
		].join("\n"),
	);
	assert.match(page.html, /<pre class="shiki /);
	assert.match(page.html, /<code class="language-typescript"/);
	assert.match(page.html, /--shiki-light:#[^";]+;--shiki-dark:#[^";]+/);
	assert.match(page.html, /<pre><code class="language-unrecognized">&lt;tag&gt;/);
	assert.doesNotMatch(page.html, /<tag>/);
});

test("Mermaid diagrams provide escaped source before the browser renderer loads", () => {
	for (const path of ["/docs/api/crypto", "/docs/features/6.trust-marks"]) {
		const page = renderDocumentation(path);
		assert.ok(page);
		assert.match(
			page.html,
			/<figure class="docs-diagram" data-mermaid><div data-diagram-output><\/div>/,
		);
		assert.match(page.html, /<details open><summary>Diagram source<\/summary>/);
		assert.match(page.html, /<code class="language-mermaid"/);
	}
	const page = renderMarkdown("README.md", '```mermaid\nflowchart LR\nA["A < B & C"] --> D\n```');
	assert.match(page.html, /&(?:lt|#60|#x3c);/i);
	assert.match(page.html, /&(?:amp|#38|#x26);/i);
	assert.doesNotMatch(page.html, /A < B/);
});
