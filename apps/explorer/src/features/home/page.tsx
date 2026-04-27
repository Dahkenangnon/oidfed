import { Button } from "@oidfed/ui";
import { ArrowUpRight, BookOpen } from "lucide-react";
import { useNavigate } from "react-router";
import { usePageTitle } from "@/hooks/use-page-title";

export function HomePage() {
	usePageTitle("OidFed Explorer");
	const navigate = useNavigate();

	return (
		<>
			<HeroStyles />
			<section className="relative -mx-4 flex min-h-[calc(100svh-8rem)] items-center justify-center overflow-hidden px-4 py-16 md:-mx-6 md:px-6 lg:-mx-8 lg:px-8 lg:py-24">
				{/* Dot grid background */}
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

				<div className="relative mx-auto max-w-3xl text-center fade-rise">
					{/* Signal badge */}
					<div className="inline-flex items-center gap-2.5 rounded-full bg-primary px-3.5 py-1.5 font-mono text-[10.5px] uppercase tracking-[0.2em] text-primary-foreground shadow-sm ring-1 ring-primary/20">
						<span className="relative inline-flex size-1.5 items-center justify-center" aria-hidden>
							<span className="absolute inline-flex size-full animate-ping rounded-full bg-primary-foreground opacity-70" />
							<span className="relative inline-flex size-1.5 rounded-full bg-primary-foreground" />
						</span>
						<span className="tabular-nums">§00</span>
						<span className="h-3 w-px bg-primary-foreground/40" aria-hidden />
						<span>Explorer · v0.2.0 pre-release</span>
					</div>

					{/* Headline */}
					<h1 className="mt-8 font-heading text-[40px] font-bold leading-[1.02] tracking-[-0.03em] text-balance sm:text-[56px] lg:text-[68px] xl:text-[76px]">
						<span className="block">Explore any</span>
						<span className="block bg-gradient-to-r from-brand-600 via-brand-500 to-brand-300 bg-clip-text text-transparent dark:from-brand-300 dark:via-brand-400 dark:to-brand-500">
							OpenID Federation.
						</span>
					</h1>

					{/* Body */}
					<p className="mx-auto mt-6 max-w-2xl text-lg leading-relaxed text-muted-foreground text-balance">
						Resolve trust chains, inspect entity configurations, verify trust marks, and browse
						federation topology — live, in your browser.
					</p>

					{/* How to start */}
					<p className="mx-auto mt-4 max-w-xl text-[15px] leading-relaxed text-muted-foreground/80">
						Paste an Entity ID into the{" "}
						<code className="rounded-sm bg-muted px-1.5 py-0.5 font-mono text-[13px] tracking-tight text-foreground">
							Entity Inspector
						</code>{" "}
						to begin, or pick a tool from the sidebar.
					</p>

					{/* CTAs */}
					<div className="mt-10 flex flex-wrap items-center justify-center gap-3">
						<Button onClick={() => navigate("/entity")} className="group">
							Open Entity Inspector
							<ArrowUpRight className="ml-1.5 size-4 transition-transform group-hover:-translate-y-0.5 group-hover:translate-x-0.5" />
						</Button>
						<Button
							variant="outline"
							render={
								<a
									href="https://learn.oidfed.com"
									target="_blank"
									rel="noopener noreferrer"
									aria-label="Learn OpenID Federation"
								/>
							}
						>
							<BookOpen className="mr-2 size-4" />
							Learn OpenID Federation
						</Button>
					</div>

					{/* Meta row */}
					<div className="mt-10 flex flex-wrap items-center justify-center gap-x-6 gap-y-2 font-mono text-[11px] uppercase tracking-[0.16em] text-muted-foreground">
						<span className="flex items-center gap-1.5">
							<span className="inline-block size-1.5 rounded-full bg-emerald-500" />
							Runs in your browser
						</span>
						<span className="flex items-center gap-1.5">
							<span className="inline-block size-1.5 rounded-full bg-brand-500" />
							No install
						</span>
						<span className="flex items-center gap-1.5">
							<span className="inline-block size-1.5 rounded-full bg-emerald-500" />
							Zero tracking
						</span>
					</div>
				</div>
			</section>
		</>
	);
}

function HeroStyles() {
	return (
		<style>{`
			@keyframes fade-rise {
				from { opacity: 0; transform: translateY(12px); }
				to { opacity: 1; transform: translateY(0); }
			}
			.fade-rise { animation: fade-rise 0.8s cubic-bezier(0.22, 1, 0.36, 1) both; }

			@media (prefers-reduced-motion: reduce) {
				.fade-rise { animation: none !important; }
			}
		`}</style>
	);
}
