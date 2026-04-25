import { List } from "lucide-react";
import { useEffect, useState } from "react";

interface TocHeading {
	id: string;
	text: string;
	level: 2 | 3;
}

/**
 * Auto-generates a right-rail table of contents by scanning the current document
 * for `<h2>` / `<h3>` elements with an `id`. Highlights the heading currently in
 * view via IntersectionObserver.
 *
 * Sticky on lg+ screens. Collapsed by default on small screens.
 */
export function LessonTOC() {
	const [headings, setHeadings] = useState<TocHeading[]>([]);
	const [activeId, setActiveId] = useState<string>("");

	useEffect(() => {
		// Collect headings from the article rendered below.
		const nodes = Array.from(
			document.querySelectorAll<HTMLHeadingElement>("article h2[id], article h3[id]"),
		);
		const parsed: TocHeading[] = nodes.map((node) => ({
			id: node.id,
			text: node.textContent ?? "",
			level: node.tagName === "H2" ? 2 : 3,
		}));
		setHeadings(parsed);

		if (nodes.length === 0) return;

		// Track which heading is currently in view.
		const observer = new IntersectionObserver(
			(entries) => {
				const visible = entries
					.filter((e) => e.isIntersecting)
					.sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
				if (visible[0]) setActiveId(visible[0].target.id);
			},
			{ rootMargin: "-80px 0px -60% 0px", threshold: 0 },
		);
		nodes.forEach((n) => observer.observe(n));
		return () => observer.disconnect();
	}, []);

	if (headings.length === 0) return null;

	return (
		<nav
			aria-label="Table of contents"
			className="max-h-[calc(100svh-6rem)] overflow-y-auto"
		>
			<div className="flex items-center gap-2 font-mono text-[10.5px] uppercase tracking-[0.18em] text-muted-foreground">
				<List className="size-3.5" aria-hidden />
				<span>On this page</span>
				<span className="h-px flex-1 bg-border" aria-hidden />
			</div>
			<ul className="mt-3 space-y-1.5 text-[13px] leading-relaxed">
				{headings.map((h) => {
					const isActive = h.id === activeId;
					return (
						<li
							key={h.id}
							className={h.level === 3 ? "pl-3" : undefined}
						>
							<a
								href={`#${h.id}`}
								className={
									isActive
										? "block truncate border-l-2 border-brand-500 pl-2 text-foreground transition-colors"
										: "block truncate border-l-2 border-transparent pl-2 text-muted-foreground transition-colors hover:border-border hover:text-foreground"
								}
							>
								{h.text}
							</a>
						</li>
					);
				})}
			</ul>
		</nav>
	);
}
