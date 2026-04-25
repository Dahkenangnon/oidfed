import type { ReactNode } from "react";

interface FigureProps {
	caption: ReactNode;
	children: ReactNode;
	/** Figure number (e.g., "Fig. 4"). If provided, rendered in mono before the caption. */
	number?: string | undefined;
}

/**
 * Wraps a diagram (typically an inline SVG) with a numbered caption beneath.
 * Uses the scientific-aesthetic convention: small mono-tracking caption under the figure.
 */
export function Figure({ caption, children, number }: FigureProps) {
	return (
		<figure className="my-8 rounded-xl border border-border/60 bg-card/40 p-4 sm:p-6">
			<div className="flex justify-center">{children}</div>
			<figcaption className="mt-4 border-t border-border/60 pt-3 text-center font-mono text-[11px] uppercase tracking-[0.16em] text-muted-foreground">
				{number && <span className="mr-2 tabular-nums text-brand-600 dark:text-brand-400">{number}</span>}
				<span className="normal-case tracking-normal">{caption}</span>
			</figcaption>
		</figure>
	);
}
