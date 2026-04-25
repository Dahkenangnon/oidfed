import { Button } from "@oidfed/ui";
import { ArrowUpRight, BookOpen, Compass, Library, ScrollText } from "lucide-react";
import { Link, useLocation } from "react-router";

export function meta() {
	return [{ title: "404 — Page Not Found | Learn OpenID Federation" }];
}

const suggestions = [
	{
		icon: ScrollText,
		title: "Start the course",
		description: "Begin at Lesson 01 — what federation is and why it exists.",
		to: "/lessons/what-is-federation",
		external: false,
	},
	{
		icon: Compass,
		title: "View the curriculum",
		description: "All 15 lessons grouped by phase, on the course home.",
		to: "/#curriculum",
		external: false,
	},
	{
		icon: Library,
		title: "Browse the glossary",
		description: "Every key OpenID Federation term, defined and §-linked.",
		to: "/lessons/glossary",
		external: false,
	},
	{
		icon: BookOpen,
		title: "Read the spec",
		description: "OpenID Federation 1.0 — the authoritative source.",
		to: "https://openid.net/specs/openid-federation-1_0.html",
		external: true,
	},
] as const;

export default function NotFound() {
	const location = useLocation();
	const attempted = location.pathname || "/";

	return (
		<div className="flex min-h-svh flex-col">
			<section className="relative flex flex-1 items-center justify-center overflow-hidden border-b border-border/60 px-6 py-20 lg:py-28">
				{/* Dot grid */}
				<div
					aria-hidden
					className="pointer-events-none absolute inset-0 opacity-[0.45] [mask-image:radial-gradient(ellipse_at_center,black_20%,transparent_75%)]"
					style={{
						backgroundImage:
							"radial-gradient(currentColor 1px, transparent 1px), radial-gradient(currentColor 1px, transparent 1px)",
						backgroundSize: "28px 28px, 28px 28px",
						backgroundPosition: "0 0, 14px 14px",
						color: "oklch(var(--muted-foreground) / 0.18)",
					}}
				/>
				{/* Accent glow */}
				<div
					aria-hidden
					className="pointer-events-none absolute left-1/2 top-0 -z-10 h-[380px] w-[900px] -translate-x-1/2 rounded-full bg-brand-500/10 blur-3xl dark:bg-brand-500/15"
				/>

				<div className="relative mx-auto w-full max-w-3xl text-center">
					{/* Signal badge */}
					<div className="inline-flex items-center gap-2.5 rounded-full bg-primary px-3.5 py-1.5 font-mono text-[10.5px] uppercase tracking-[0.2em] text-primary-foreground shadow-sm ring-1 ring-primary/20">
						<span className="relative inline-flex size-1.5 items-center justify-center" aria-hidden>
							<span className="absolute inline-flex size-full animate-ping rounded-full bg-primary-foreground opacity-70" />
							<span className="relative inline-flex size-1.5 rounded-full bg-primary-foreground" />
						</span>
						<span className="tabular-nums">§404</span>
						<span className="h-3 w-px bg-primary-foreground/40" aria-hidden />
						<span>Not found</span>
					</div>

					{/* Headline */}
					<h1 className="mt-6 font-heading text-[40px] font-bold leading-[1.02] tracking-[-0.03em] text-balance sm:text-[56px] lg:text-[68px]">
						<span className="block">No statement</span>
						<span className="block bg-gradient-to-r from-brand-600 via-brand-500 to-brand-300 bg-clip-text text-transparent dark:from-brand-300 dark:via-brand-400 dark:to-brand-500">
							at this path.
						</span>
					</h1>

					{/* Body */}
					<p className="mx-auto mt-6 max-w-xl text-lg leading-relaxed text-muted-foreground text-balance">
						The page you're looking for doesn't exist or has been moved. The course is still here —
						pick up where you'd like to continue.
					</p>

					{/* Attempted path — mono diagnostic */}
					<div className="mx-auto mt-6 inline-flex max-w-full items-center gap-2 rounded-md border border-border/60 bg-card/60 px-3 py-1.5 font-mono text-[11px] uppercase tracking-[0.16em] text-muted-foreground">
						<span className="text-muted-foreground/70">Attempted</span>
						<span className="h-3 w-px bg-border" aria-hidden />
						<span className="truncate font-medium normal-case tracking-tight text-foreground">
							{attempted}
						</span>
					</div>

					{/* Primary CTA */}
					<div className="mt-10 flex flex-wrap items-center justify-center gap-3">
						<Button size="lg" render={<Link to="/" />} className="group">
							Back to course home
							<ArrowUpRight className="ml-1.5 size-4 transition-transform group-hover:-translate-y-0.5 group-hover:translate-x-0.5" />
						</Button>
						<Button
							variant="outline"
							size="lg"
							render={<Link to="/lessons/what-is-federation" />}
						>
							Start Lesson 01
						</Button>
					</div>

					{/* Suggestions */}
					<div className="mx-auto mt-12 max-w-2xl">
						<div className="flex items-center gap-3 font-mono text-[10.5px] uppercase tracking-[0.18em] text-muted-foreground">
							<span className="inline-flex size-1.5 rounded-full bg-brand-500" aria-hidden />
							<span>Try one of these instead</span>
							<span className="h-px flex-1 bg-border" aria-hidden />
						</div>
						<ul className="mt-4 grid gap-2 not-prose sm:grid-cols-2">
							{suggestions.map((s) => {
								const Icon = s.icon;
								const inner = (
									<div className="group grid h-full grid-cols-[auto_1fr_auto] items-start gap-3 rounded-xl border border-border/60 bg-card/40 p-4 text-left transition-colors hover:bg-muted/50">
										<Icon
											className="mt-0.5 size-4 shrink-0 text-brand-600 dark:text-brand-400"
											aria-hidden
										/>
										<div className="min-w-0">
											<div className="font-heading text-[14.5px] font-semibold leading-snug tracking-tight text-foreground">
												{s.title}
											</div>
											<p className="mt-0.5 text-[13px] leading-relaxed text-muted-foreground">
												{s.description}
											</p>
										</div>
										<ArrowUpRight className="size-4 shrink-0 text-muted-foreground transition-colors group-hover:text-brand-500" />
									</div>
								);
								return (
									<li key={s.title}>
										{s.external ? (
											<a href={s.to} target="_blank" rel="noopener noreferrer" className="block">
												{inner}
											</a>
										) : (
											<Link to={s.to} className="block">
												{inner}
											</Link>
										)}
									</li>
								);
							})}
						</ul>
					</div>
				</div>
			</section>

			{/* Mono footer strip */}
			<footer className="border-t border-border/60 bg-background">
				<div className="mx-auto flex max-w-6xl items-center justify-between gap-3 px-6 py-3 font-mono text-[10.5px] uppercase tracking-[0.16em] text-muted-foreground">
					<span className="flex items-center gap-1.5">
						<span className="inline-block size-1.5 rounded-full bg-amber-500" aria-hidden />
						HTTP 404
					</span>
					<span className="hidden sm:inline">Learn · OpenID Federation 1.0</span>
				</div>
			</footer>
		</div>
	);
}
