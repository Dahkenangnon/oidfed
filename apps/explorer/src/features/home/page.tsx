import { Button } from "@oidfed/ui";
import { ArrowUpRight } from "lucide-react";
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
					</div>

					{/* First-party demo nudge — loads the fed.oidfed.com reference deployment's
					    Trust Anchors via the Settings page URL-import flow. */}
					<p className="mt-4 text-sm text-muted-foreground">
						First time here?{" "}
						<a
							href="https://explore.oidfed.com/#/settings?import=https%3A%2F%2Fraw.githubusercontent.com%2FDahkenangnon%2Ffed-oidfed-com%2Fmain%2Fpages%2Fexplorer-settings.json"
							target="_blank"
							rel="noopener noreferrer"
							className="inline-flex items-center gap-1 font-medium text-brand-500 hover:text-brand-600"
						>
							Try the fed.oidfed.com reference deployment
							<ArrowUpRight className="size-3.5" />
						</a>
					</p>
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
