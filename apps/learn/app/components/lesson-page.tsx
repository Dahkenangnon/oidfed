import type { ReactNode } from "react";
import type { Lesson } from "~/data/lessons";
import { getLessonNav, phases } from "~/data/lessons";
import {
	FurtherReading,
	type ExternalRef,
	type RFCReference,
	type SpecSectionRef,
} from "./further-reading";
import { LessonNav } from "./lesson-nav";
import { LessonTOC } from "./lesson-toc";
import { ReadingMeta, estimateMinutes } from "./reading-meta";

interface LessonPageProps {
	lesson: Lesson;
	children: ReactNode;
	/** Optional per-lesson Further Reading block contents. */
	furtherReading?:
		| {
				specSections?: SpecSectionRef[];
				rfcs?: RFCReference[];
				external?: ExternalRef[];
		  }
		| undefined;
	/** Pre-computed minutes override; defaults to a rough 3 min estimate. */
	minutes?: number | undefined;
	/** Last review date (ISO). Defaults to the shared handle value from the route. */
	lastReviewed?: string | undefined;
}

/**
 * Shared wrapper for every lesson route. Renders a scientific-aesthetic lesson header
 * (phase signal, large heading, reading metadata), the prose body capped at ~68ch for
 * comfortable line length, a sticky right-rail TOC on large screens, and an optional
 * end-of-lesson Further Reading block before the prev/next nav.
 */
export function LessonPage({
	lesson,
	children,
	furtherReading,
	minutes,
	lastReviewed = "2026-04-25",
}: LessonPageProps) {
	const { prev, next } = getLessonNav(lesson.number);
	const phase = phases[lesson.phase];
	const readingMinutes = minutes ?? estimateMinutes(typeof children === "string" ? children : "");
	const phaseNum = String(lesson.number).padStart(2, "0");

	return (
		<div className="flex w-full flex-col gap-10 px-4 py-10 sm:px-6 lg:flex-row lg:items-start lg:gap-12 lg:px-10 lg:py-14">
			<article className="w-full min-w-0 flex-1">
				<header className="mb-10 border-b border-border/60 pb-8">
					<SignalLabel id={phaseNum} label={`Lesson · ${phase.label}`} phaseColor={phase.color} />
					<h1 className="mt-5 font-heading text-[32px] font-bold leading-[1.05] tracking-[-0.03em] text-balance sm:text-[40px] lg:text-[52px]">
						{lesson.title}
					</h1>
					<p className="mt-3 max-w-[80ch] text-lg leading-relaxed text-muted-foreground text-balance">
						{lesson.subtitle}
					</p>
					<ReadingMeta
						minutes={readingMinutes || 3}
						lastReviewed={lastReviewed}
						phaseLabel={phase.label}
					/>
				</header>

				<div className="prose prose-neutral dark:prose-invert max-w-[85ch] prose-headings:font-heading prose-headings:tracking-tight prose-h2:mt-12 prose-h2:text-[26px] prose-h2:font-semibold prose-h3:text-[19px] prose-h3:font-semibold prose-p:leading-relaxed prose-p:text-[15.5px] prose-li:my-1 prose-li:text-[15.5px] prose-a:text-brand-600 dark:prose-a:text-brand-400 prose-a:underline-offset-2 prose-strong:text-foreground prose-code:rounded-sm prose-code:bg-muted prose-code:px-1 prose-code:py-0 prose-code:font-mono prose-code:text-[13px] prose-code:before:content-none prose-code:after:content-none">
					{children}
				</div>

				{furtherReading && (
					<div className="max-w-[85ch]">
						<FurtherReading {...furtherReading} />
					</div>
				)}

				<div className="max-w-[85ch]">
					<LessonNav prev={prev} next={next} />
				</div>
			</article>

			<aside className="hidden w-56 shrink-0 lg:sticky lg:top-6 lg:block">
				<LessonTOC />
			</aside>
		</div>
	);
}

function SignalLabel({
	id,
	label,
	phaseColor,
}: {
	id: string;
	label: string;
	phaseColor: string;
}) {
	return (
		<div className="flex items-center gap-3 font-mono text-[11px] uppercase tracking-[0.18em] text-muted-foreground">
			<span className={`inline-flex size-1.5 rounded-full bg-brand-500 ${phaseColor}`} aria-hidden />
			<span className={`tabular-nums ${phaseColor}`}>§{id}</span>
			<span className="h-px w-8 bg-border" aria-hidden />
			<span>{label}</span>
		</div>
	);
}
