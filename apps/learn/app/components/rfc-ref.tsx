import { ArrowUpRight } from "lucide-react";

interface RFCRefProps {
	/** RFC number, e.g. 9101 */
	rfc: number;
	/** Optional human-readable title for the hover tooltip / accessible name */
	title?: string | undefined;
	/** Render-size hint. Default "inline" for use inside prose. */
	size?: "inline" | "block" | undefined;
}

/**
 * Inline chip for IETF RFC references.
 * Example: <RFCRef rfc={9101} title="JWT-Secured Authorization Request" />
 */
export function RFCRef({ rfc, title, size = "inline" }: RFCRefProps) {
	const href = `https://datatracker.ietf.org/doc/html/rfc${rfc}`;
	const accessibleTitle = title ? `RFC ${rfc} · ${title}` : `RFC ${rfc}`;
	const base =
		size === "inline"
			? "inline-flex items-center gap-0.5 rounded-sm border border-border/80 bg-muted/60 px-1.5 py-0 font-mono text-[11px] font-medium text-foreground no-underline tabular-nums transition-colors hover:bg-muted hover:border-border"
			: "inline-flex items-center gap-1 rounded-md border border-border/80 bg-muted/60 px-2 py-1 font-mono text-xs font-medium text-foreground no-underline tabular-nums transition-colors hover:bg-muted hover:border-border";
	return (
		<a
			href={href}
			target="_blank"
			rel="noopener noreferrer"
			title={accessibleTitle}
			aria-label={accessibleTitle}
			className={base}
		>
			<span>RFC&nbsp;{rfc}</span>
			{title && size === "block" && <span className="truncate normal-case">{title}</span>}
			<ArrowUpRight className="size-3 opacity-60" aria-hidden />
		</a>
	);
}
