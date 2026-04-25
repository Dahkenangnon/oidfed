import { Clock, Tag } from "lucide-react";

interface ReadingMetaProps {
	/** Estimated reading time in minutes (computed by parent from word count). */
	minutes: number;
	/** ISO date string for last content review. */
	lastReviewed?: string | undefined;
	/** Curriculum phase label for this lesson (e.g., "Foundation"). */
	phaseLabel?: string | undefined;
}

/**
 * Compact metadata strip under a lesson title:
 * "04 min read · Last reviewed 2026-04-25 · Foundation"
 */
export function ReadingMeta({ minutes, lastReviewed, phaseLabel }: ReadingMetaProps) {
	return (
		<div className="mt-4 flex flex-wrap items-center gap-x-5 gap-y-2 font-mono text-[10.5px] uppercase tracking-[0.16em] text-muted-foreground">
			<span className="inline-flex items-center gap-1.5">
				<Clock className="size-3" aria-hidden />
				<span className="tabular-nums">{String(minutes).padStart(2, "0")}&nbsp;min read</span>
			</span>
			{lastReviewed && (
				<span className="inline-flex items-center gap-1.5">
					<span className="inline-block size-1.5 rounded-full bg-emerald-500" aria-hidden />
					<span className="tabular-nums">Last reviewed {lastReviewed}</span>
				</span>
			)}
			{phaseLabel && (
				<span className="inline-flex items-center gap-1.5">
					<Tag className="size-3" aria-hidden />
					<span>{phaseLabel}</span>
				</span>
			)}
		</div>
	);
}

/** Estimate reading time from a JSX children ReactNode tree. Approx. 220 words per minute. */
export function estimateMinutes(text: string): number {
	const words = text.trim().split(/\s+/).filter(Boolean).length;
	return Math.max(1, Math.round(words / 220));
}
