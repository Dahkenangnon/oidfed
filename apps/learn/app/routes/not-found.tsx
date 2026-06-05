import { Button } from "@oidfed/ui";
import { ArrowLeft, BookOpen } from "lucide-react";
import { Link } from "react-router";

export function meta() {
	return [
		{ title: "404 — Page Not Found | Learn OpenID Federation" },
		{ name: "robots", content: "noindex,nofollow" },
	];
}

export default function NotFound() {
	return (
		<main className="flex min-h-svh items-center justify-center px-6 py-16">
			<section className="w-full max-w-md text-center">
				<p className="font-mono text-sm font-medium uppercase tracking-[0.2em] text-muted-foreground">
					404
				</p>
				<h1 className="mt-4 font-heading text-4xl font-semibold tracking-tight">
					Page not found
				</h1>
				<p className="mx-auto mt-4 max-w-sm text-sm leading-relaxed text-muted-foreground">
					This lesson or course page does not exist.
				</p>

				<div className="mt-8 flex flex-col justify-center gap-3 sm:flex-row">
					<Button render={<Link to="/" />}>
						<ArrowLeft className="size-4" />
						Course home
					</Button>
					<Button variant="outline" render={<Link to="/lessons/what-is-federation" />}>
						<BookOpen className="size-4" />
						Start lesson 01
					</Button>
				</div>
			</section>
		</main>
	);
}
