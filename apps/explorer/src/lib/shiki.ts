import type { createHighlighter } from "shiki";

type Highlighter = Awaited<ReturnType<typeof createHighlighter>>;

let highlighterPromise: Promise<Highlighter> | undefined;

export function getHighlighter(): Promise<Highlighter> {
	if (!highlighterPromise) {
		highlighterPromise = import("shiki").then((shiki) =>
			shiki.createHighlighter({
				themes: ["dark-plus", "light-plus"],
				langs: ["json", "javascript"],
			}),
		);
	}
	return highlighterPromise;
}
