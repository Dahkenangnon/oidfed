import { useEffect, useRef } from "react";

let mermaidPromise: Promise<typeof import("mermaid")["default"]> | undefined;
let diagramId = 0;

function loadMermaid() {
	return (mermaidPromise ??= import("mermaid").then(({ default: mermaid }) => {
		mermaid.initialize({
			startOnLoad: false,
			securityLevel: "strict",
			htmlLabels: false,
			suppressErrorRendering: true,
			theme: "neutral",
			flowchart: { wrappingWidth: 240 },
		});
		return mermaid;
	}));
}

export function DocsArticle({ html }: { html: string }) {
	const article = useRef<HTMLElement>(null);

	useEffect(() => {
		const diagrams = article.current?.querySelectorAll("[data-mermaid]");
		if (!diagrams?.length) return;
		let active = true;

		const renderDiagrams = async () => {
			const mermaid = await loadMermaid();
			for (const diagram of diagrams) {
				if (!active) return;
				const source = diagram.querySelector("pre code")?.textContent;
				const output = diagram.querySelector<HTMLElement>("[data-diagram-output]");
				if (!source || !output) continue;

				try {
					const { svg } = await mermaid.render(`docs-diagram-${++diagramId}`, source);
					if (!active || !output.isConnected) return;
					// Mermaid sanitizes SVG in strict mode. The input comes from repository docs.
					output.innerHTML = svg;
					output.tabIndex = 0;
					output.setAttribute("role", "region");
					output.setAttribute("aria-label", "Diagram");
					const details = diagram.querySelector("details");
					if (details) details.open = false;
				} catch {
					// Keep the source available if Mermaid cannot parse this diagram.
				}
			}
		};

		void renderDiagrams().catch(() => {
			// The source remains visible if the diagram renderer fails to load.
		});
		return () => {
			active = false;
		};
	}, [html]);

	// biome-ignore lint/security/noDangerouslySetInnerHtml: server-only Markdown rendering escapes raw HTML and validates URLs
	return (
		<article ref={article} className="docs-article" dangerouslySetInnerHTML={{ __html: html }} />
	);
}
