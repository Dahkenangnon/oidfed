import type { ReactNode } from "react";

/**
 * Shared design primitives for the home app — used across every route so the
 * "technical broadcast" visual language (signal markers, mono accents, editorial
 * splits, list-style tables) stays consistent end-to-end.
 */

export function SectionTitle({ children }: { children: ReactNode }) {
	return (
		<h2 className="font-heading text-3xl font-semibold tracking-[-0.02em] text-balance sm:text-4xl">
			{children}
		</h2>
	);
}

export function SectionIntro({ children }: { children: ReactNode }) {
	return (
		<p className="mt-4 max-w-xl text-[15px] leading-relaxed text-muted-foreground">{children}</p>
	);
}

/** Mono micro-header used above list-style tables (Packages, Deployments, etc.). */
export function RowHeader({
	icon,
	label,
	right,
}: {
	icon: ReactNode;
	label: string;
	right?: ReactNode;
}) {
	return (
		<div className="flex items-center gap-3 font-mono text-[11px] uppercase tracking-[0.18em] text-muted-foreground">
			<span className="text-muted-foreground">{icon}</span>
			<span>{label}</span>
			<span className="h-px flex-1 bg-border" />
			{right && <span className="tabular-nums">{right}</span>}
		</div>
	);
}

/** Compact flag/region pill used in unified lists. */
export function RegionPill({ region }: { region: string }) {
	return (
		<span className="inline-flex h-5 min-w-[28px] items-center justify-center rounded-sm border border-border/80 bg-muted px-1.5 font-mono text-[9px] font-semibold tracking-wider tabular-nums text-muted-foreground">
			{region}
		</span>
	);
}
