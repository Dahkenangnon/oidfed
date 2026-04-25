import { ArrowUpRight } from "lucide-react";

const SPEC_BASE = "https://openid.net/specs/openid-federation-1_0.html";

interface SpecRefProps {
	/** Section number, e.g. "7.2.1" — renders as `§7.2.1 ↗` and links to #section-7.2.1 */
	sec: string;
	/** Optional human-readable title for the hover tooltip / accessible name */
	title?: string | undefined;
	/** Render-size hint. Default "inline" for use inside prose. */
	size?: "inline" | "block" | undefined;
}

/**
 * Inline chip for OpenID Federation 1.0 specification references.
 * Example: <SpecRef sec="7.2.1" title="Trust Mark Delegation" />
 */
export function SpecRef({ sec, title, size = "inline" }: SpecRefProps) {
	const href = `${SPEC_BASE}#section-${sec}`;
	const accessibleTitle = title ? `§${sec} · ${title}` : `OpenID Federation 1.0 §${sec}`;
	const base =
		size === "inline"
			? "inline-flex items-center gap-0.5 rounded-sm border border-brand-500/30 bg-brand-500/5 px-1.5 py-0 font-mono text-[11px] font-medium text-brand-700 no-underline tabular-nums transition-colors hover:bg-brand-500/10 hover:border-brand-500/50 dark:border-brand-400/30 dark:bg-brand-400/10 dark:text-brand-300"
			: "inline-flex items-center gap-1 rounded-md border border-brand-500/30 bg-brand-500/5 px-2 py-1 font-mono text-xs font-medium text-brand-700 no-underline tabular-nums transition-colors hover:bg-brand-500/10 hover:border-brand-500/50 dark:border-brand-400/30 dark:bg-brand-400/10 dark:text-brand-300";
	return (
		<a
			href={href}
			target="_blank"
			rel="noopener noreferrer"
			title={accessibleTitle}
			aria-label={accessibleTitle}
			className={base}
		>
			<span>§{sec}</span>
			{title && size === "block" && <span className="truncate normal-case">{title}</span>}
			<ArrowUpRight className="size-3 opacity-60" aria-hidden />
		</a>
	);
}
