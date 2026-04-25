import { buttonVariants } from "@oidfed/ui";
import { ArrowLeft, Compass, XCircle } from "lucide-react";
import { Link } from "react-router";
import { DotGrid, SignalLabel } from "../components/section-ui";

export function meta() {
	return [
		{ title: "404 — Page Not Found | @oidfed" },
		{ name: "robots", content: "noindex,nofollow" },
	];
}

export default function NotFound() {
	return (
		<section className="relative flex min-h-[calc(100vh-3.5rem-4rem)] items-center justify-center overflow-hidden">
			<DotGrid />
			<div
				aria-hidden
				className="pointer-events-none absolute left-1/2 top-1/3 -z-10 h-[420px] w-[720px] -translate-x-1/2 rounded-full bg-brand-500/10 blur-3xl dark:bg-brand-500/15"
			/>

			<div className="relative mx-auto w-full max-w-2xl px-6 py-16 text-center">
				<div className="flex justify-center">
					<SignalLabel id="404" label="Resource not found" />
				</div>

				<h1 className="mt-10 font-heading text-[120px] font-bold leading-none tracking-[-0.05em] sm:text-[160px] lg:text-[200px]">
					<span className="bg-gradient-to-br from-brand-600 via-brand-500 to-brand-300 bg-clip-text text-transparent dark:from-brand-300 dark:via-brand-400 dark:to-brand-500">
						404
					</span>
				</h1>

				<p className="mx-auto mt-6 max-w-md text-[15px] leading-relaxed text-muted-foreground text-balance">
					The page you're looking for doesn't exist — or the entity statement for this route
					has expired.
				</p>

				{/* Failed-chain status panel (inverse of the hero's successful-chain panel) */}
				<div className="mx-auto mt-10 max-w-sm rounded-lg border border-border/60 bg-background/80 p-4 text-left shadow-sm backdrop-blur-md">
					<div className="flex items-center gap-2">
						<XCircle className="size-3.5 text-red-500" />
						<span className="font-mono text-[11px] tracking-wide">chain.invalid</span>
						<span className="ml-auto rounded-sm bg-red-500/10 px-1.5 py-0.5 font-mono text-[9px] font-medium uppercase tracking-wider text-red-600 dark:text-red-400">
							404
						</span>
					</div>
					<div className="mt-2.5 font-mono text-[10.5px] leading-relaxed text-muted-foreground">
						<div className="flex justify-between">
							<span>entity</span>
							<span className="tabular-nums text-foreground">&lt;unresolved&gt;</span>
						</div>
						<div className="flex justify-between">
							<span>reason</span>
							<span className="tabular-nums text-foreground">route_not_found</span>
						</div>
						<div className="flex justify-between">
							<span>retry</span>
							<span className="tabular-nums text-foreground">follow authority_hints ↑</span>
						</div>
					</div>
				</div>

				<div className="mt-10 flex flex-wrap items-center justify-center gap-3">
					<Link to="/" className={`${buttonVariants()} group`}>
						<ArrowLeft className="mr-1.5 size-4 transition-transform group-hover:-translate-x-0.5" />
						Back to home
					</Link>
					<Link
						to="/ecosystem"
						className={`${buttonVariants({ variant: "outline" })} group`}
					>
						<Compass className="mr-1.5 size-4" />
						Browse ecosystem
					</Link>
				</div>
			</div>
		</section>
	);
}
