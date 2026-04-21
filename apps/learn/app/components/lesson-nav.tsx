import { Button } from "@oidfed/ui";
import { ChevronLeft, ChevronRight } from "lucide-react";
import { Link } from "react-router";
import type { Lesson } from "~/data/lessons";

export function LessonNav({ prev, next }: { prev: Lesson | undefined; next: Lesson | undefined }) {
	return (
		<nav className="flex items-center justify-between mt-12 pt-6 border-t border-border">
			{prev ? (
				<Button variant="outline" size="sm" render={<Link to={`/lessons/${prev.slug}`} />}>
					<ChevronLeft className="size-4 mr-1" />
					{prev.title}
				</Button>
			) : (
				<div />
			)}
			{next ? (
				<Button variant="outline" size="sm" render={<Link to={`/lessons/${next.slug}`} />}>
					{next.title}
					<ChevronRight className="size-4 ml-1" />
				</Button>
			) : (
				<div />
			)}
		</nav>
	);
}
