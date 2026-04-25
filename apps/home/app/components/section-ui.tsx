import type { ReactNode } from "react";

/**
 * Shared design primitives for the home app — used across every route so the
 * "technical broadcast" visual language (signal markers, mono accents, editorial
 * splits, list-style tables) stays consistent end-to-end.
 */

export function SignalLabel({ id, label }: { id: string; label: string }) {
	return (
		<div className="flex items-center gap-3 font-mono text-[11px] uppercase tracking-[0.18em] text-muted-foreground">
			<span className="inline-flex size-1.5 rounded-full bg-brand-500" aria-hidden />
			<span className="tabular-nums">§{id}</span>
			<span className="h-px w-8 bg-border" aria-hidden />
			<span>{label}</span>
		</div>
	);
}

export function SectionTitle({ children }: { children: ReactNode }) {
	return (
		<h2 className="mt-6 font-heading text-3xl font-semibold tracking-[-0.02em] text-balance sm:text-4xl">
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

/** Tiny status dot-label used in hero meta rows, footer status bar, etc. */
export function StatusDot({
	tone = "brand",
	children,
}: {
	tone?: "brand" | "success" | "warn";
	children: ReactNode;
}) {
	const dot =
		tone === "success" ? "bg-emerald-500" : tone === "warn" ? "bg-amber-500" : "bg-brand-500";
	return (
		<span className="flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-[0.16em] text-muted-foreground">
			<span className={`inline-block size-1.5 rounded-full ${dot}`} />
			{children}
		</span>
	);
}

/** Dot-grid background layer, used behind hero sections. */
export function DotGrid({ className = "" }: { className?: string }) {
	return (
		<div
			aria-hidden
			className={`pointer-events-none absolute inset-0 opacity-[0.45] [mask-image:radial-gradient(ellipse_at_center,black_20%,transparent_75%)] ${className}`}
			style={{
				backgroundImage:
					"radial-gradient(currentColor 1px, transparent 1px), radial-gradient(currentColor 1px, transparent 1px)",
				backgroundSize: "28px 28px, 28px 28px",
				backgroundPosition: "0 0, 14px 14px",
				color: "oklch(var(--muted-foreground) / 0.18)",
			}}
		/>
	);
}
