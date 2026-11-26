/** Check local documentation links using the same Markdown tokens and heading IDs as the site. */
import { readFileSync, statSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { documentation, parseDocumentationMarkdown } from "../app/lib/docs.server";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const docs = resolve(root, "docs");
const sources = [...documentation.values()]
	.filter((source) => source.endsWith(".md"))
	.map((source) => resolve(docs, source));
sources.push(resolve(root, "README.md"), resolve(root, "apps/explorer/docs/README.md"));

const parsed = new Map<string, ReturnType<typeof parseDocumentationMarkdown>>();
/** Parse each source or linked page once, including Markdown outside the docs tree. */
function readPage(path: string) {
	let page = parsed.get(path);
	if (!page) {
		page = parseDocumentationMarkdown(path, readFileSync(path, "utf8"));
		parsed.set(path, page);
	}
	return page;
}

/** Resolve local destinations, including site routes and directory README pages. */
function linkProblem(href: string, source: string): string | undefined {
	if (/^(?:[a-z][a-z0-9+.-]*:|\/\/)/i.test(href)) return;
	const [destination = "", fragment] = href.split("#", 2);
	const path = decodeURI(destination.split("?", 1)[0] ?? "");
	const anchor = fragment && decodeURIComponent(fragment);
	const route = documentation.get(path.replace(/\/$/, ""));
	if (path.startsWith("/") && !route)
		return path === "/docs" || path.startsWith("/docs/") ? "unknown documentation route" : undefined;
	const target = route ? resolve(docs, route) : path ? resolve(dirname(source), path) : source;
	const stat = statSync(target, { throwIfNoEntry: false });
	if (!stat) return "missing local target";
	if (!anchor) return;
	const page = stat.isDirectory() ? resolve(target, "README.md") : target;
	if (!page.endsWith(".md") && !route) return;
	if (!statSync(page, { throwIfNoEntry: false })?.isFile()) return "missing Markdown page";
	if (!readPage(page).headings.some(({ id }) => id === anchor)) return "missing heading anchor";
}

const selected = process.argv.slice(2);
let failures = 0;
for (const source of selected.length ? selected.map((path) => resolve(path)) : sources) {
	for (const token of readPage(source).tokens) {
		for (const child of token.children ?? []) {
			if (child.type !== "link_open") continue;
			const href = child.attrGet("href");
			if (typeof href !== "string" || !href) continue;
			let problem: string | undefined;
			try {
				problem = linkProblem(href, source);
			} catch (error) {
				if (!(error instanceof URIError)) throw error;
				problem = "invalid URL encoding";
			}
			if (!problem) continue;
			failures++;
			console.error(`${relative(root, source)}:${(token.map?.[0] ?? 0) + 1}: ${problem}: ${href}`);
		}
	}
}

if (failures) process.exitCode = 1;
else console.log(`Documentation links checked in ${selected.length || sources.length} files`);
