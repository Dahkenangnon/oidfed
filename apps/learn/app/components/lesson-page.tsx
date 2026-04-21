import { Badge } from "@oidfed/ui";
import type { Lesson } from "~/data/lessons";
import { getLessonNav, phases } from "~/data/lessons";
import { LessonNav } from "./lesson-nav";

export function LessonPage({ lesson, children }: { lesson: Lesson; children: React.ReactNode }) {
	const { prev, next } = getLessonNav(lesson.number);
	const phase = phases[lesson.phase];

	return (
		<article className="max-w-4xl mx-auto px-4 py-8 sm:px-6 lg:px-8">
			<header className="mb-8">
				<Badge variant="outline" className="mb-3">
					<span className={phase.color}>{phase.label}</span>
					<span className="mx-1.5">·</span>
					Lesson {lesson.number}
				</Badge>
				<h1 className="text-3xl font-bold tracking-tight sm:text-4xl mb-2">
					{lesson.emoji} {lesson.title}
				</h1>
				<p className="text-lg text-muted-foreground">{lesson.subtitle}</p>
			</header>
			<div className="prose prose-neutral dark:prose-invert max-w-none">{children}</div>
			<LessonNav prev={prev} next={next} />
		</article>
	);
}
