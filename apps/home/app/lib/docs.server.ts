import { readdirSync, readFileSync } from "node:fs";
import { join, posix, relative, resolve, sep } from "node:path";
import GithubSlugger from "github-slugger";
import MarkdownIt from "markdown-it";
import { highlightCode } from "./highlight.server";
import { DOCS, REPOSITORY } from "./links";

const docsRoot = resolve("../../docs");

function pathFor(source: string) {
	const page = source.replace(/(^|\/)README\.md$/, "").replace(/\.(md|ts)$/, "");
	return page ? `${DOCS}/${page.replace(/\/$/, "")}` : DOCS;
}

// Routes only resolve to files enumerated from the documentation tree.
export const documentation = new Map(
	readdirSync(docsRoot, { recursive: true, withFileTypes: true })
		.filter((entry) => entry.isFile() && /\.(md|ts)$/.test(entry.name))
		.map((entry) => relative(docsRoot, join(entry.parentPath, entry.name)).split(sep).join("/"))
		.sort()
		.map((source) => [pathFor(source), source]),
);
export const prerenderedPages = [
	"/",
	"/ecosystem",
	"/trust-journal",
	"/about",
	...documentation.keys(),
];

const sources = new Map(Array.from(documentation, ([path, source]) => [source, path]));
const markdown = new MarkdownIt({
	html: true,
	highlight: (code, language) => highlightCode(code, language),
});
const escape = markdown.utils.escapeHtml;

const renderFence = markdown.renderer.rules.fence;
markdown.renderer.rules.fence = (...args) => {
	const [tokens, index] = args;
	const token = tokens[index];
	if (!token || !/^mermaid(?:\s|$)/.test(token.info.trim())) {
		return renderFence?.(...args) ?? "";
	}
	return `<figure class="docs-diagram" data-mermaid><div data-diagram-output></div><details open><summary>Diagram source</summary>${highlightCode(token.content, "mermaid")}</details></figure>\n`;
};

function navigationTitle(source: string) {
	const firstLine = readFileSync(join(docsRoot, source), "utf8").split(/\r?\n/, 1)[0] ?? "";
	return firstLine.replace(/^#\s+/, "").trim();
}

function featureGuideTopics() {
	const guides = [...documentation].flatMap(([path, source]) => {
		const match = /^features\/(\d+)\.(?:(\d+)\.)?[^/]+\.md$/.exec(source);
		if (!match) return [];
		return [
			{
				path,
				label: navigationTitle(source),
				topic: Number(match[1]),
				order: Number(match[2] ?? 0),
			},
		];
	});
	guides.sort((a, b) => a.topic - b.topic || a.order - b.order);
	return guides
		.filter(({ order }) => order === 0)
		.map(({ label, path, topic }) => ({
			label,
			path,
			guides: guides
				.filter((guide) => guide.topic === topic && guide.order > 0)
				.map(({ label, path }) => ({ label, path })),
		}));
}

export const guideCatalog = featureGuideTopics();

export const packagePages = [...documentation].flatMap(([path, source]) =>
	/^api\/[^/]+\/(?!README\.md$)[^/]+\.md$/.test(source)
		? [{ path, label: navigationTitle(source) }]
		: [],
);

function resolveLink(href: string, source: string) {
	if (!href || href.startsWith("#") || /^[a-z][a-z0-9+.-]*:/i.test(href) || href.startsWith("//")) {
		return href;
	}
	const path = href.split(/[?#]/, 1)[0];
	if (!path || path.startsWith("/")) return href;

	let decoded: string;
	try {
		decoded = decodeURI(path);
	} catch {
		return href;
	}
	const local = posix.join(posix.dirname(source), decoded);
	const suffix = href.slice(path.length);
	const route = sources.get(local) ?? sources.get(posix.join(local, "README.md"));
	if (route) return route + suffix;

	const repoPath = posix.join("docs", local).split("/").map(encodeURIComponent).join("/");
	return `${REPOSITORY}/blob/main/${repoPath}${suffix}`;
}

export function renderDocumentation(path: string) {
	const source = documentation.get(path);
	if (!source) return undefined;

	return renderMarkdown(source, readFileSync(join(docsRoot, source), "utf8"));
}

/** Parse a page and assign the same heading IDs for rendering and link checks. */
export function parseDocumentationMarkdown(source: string, contents: string) {
	const slugger = new GithubSlugger();
	const snippet = source.endsWith(".ts");
	const tokens = markdown.parse(
		snippet ? `# ${posix.basename(source)}\n\n\`\`\`ts\n${contents}\n\`\`\`\n` : contents,
		{},
	);
	const headings = tokens.flatMap((token, index) => {
		const inline = tokens[index + 1];
		if (token.type !== "heading_open" || inline?.type !== "inline") return [];
		const label =
			inline.children
				?.map(({ content }) => content)
				.join("")
				.trim() || inline.content;
		const id = slugger.slug(label);
		token.attrSet("id", id);
		return [{ label, id, level: Number(token.tag.slice(1)) }];
	});
	return { tokens, headings };
}

export function renderMarkdown(source: string, contents: string) {
	const { tokens, headings } = parseDocumentationMarkdown(source, contents);
	let description: string | undefined;

	for (const [i, token] of tokens.entries()) {
		const inline = tokens[i + 1];
		if (
			!description &&
			token.type === "paragraph_open" &&
			inline?.type === "inline" &&
			!inline.content.startsWith("[")
		) {
			const paragraph = inline.children
				?.map(({ content }) => content)
				.join("")
				.replace(/\s+/g, " ")
				.trim();
			if (paragraph) {
				description =
					paragraph.length > 158 ? `${paragraph.slice(0, 155).replace(/\s+\S*$/, "")}…` : paragraph;
			}
		}
		for (const child of token.children ?? []) {
			const attr = child.type === "link_open" ? "href" : child.type === "image" ? "src" : null;
			const href = attr && child.attrGet(attr);
			if (attr && href) child.attrSet(attr, resolveLink(href, source));
		}
	}

	return {
		title: headings.findLast(({ level }) => level === 1)?.label ?? "Documentation",
		description:
			description ??
			"OpenID Federation guides and public JavaScript and TypeScript API reference for OidFed.",
		headings: headings.filter(({ level }) => level === 2 || level === 3),
		edit: `${REPOSITORY}/edit/main/docs/${source}`,
		html: markdown.renderer.render(tokens, markdown.options, {}),
	};
}

// Preserve the docs' collapsible sections; everything else authored as HTML is escaped.
markdown.renderer.rules.html_inline = (tokens, index) => escape(tokens[index]?.content ?? "");
markdown.renderer.rules.html_block = (tokens, index) => {
	const content = tokens[index]?.content.trim() ?? "";
	if (content.startsWith("<!--") && content.endsWith("-->")) return "";
	const summary = /^<details>\s*<summary>([^<>]*)<\/summary>$/.exec(content)?.[1];
	if (summary !== undefined) return `<details><summary>${escape(summary)}</summary>\n`;
	if (content === "</details>") return "</details>\n";
	return `<p>${escape(content)}</p>\n`;
};
