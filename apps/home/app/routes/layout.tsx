import { ExternalLink } from "lucide-react";
import { Link, Outlet, useMatches } from "react-router";
import { ThemeToggle } from "../components/theme-toggle";

export default function SiteLayout() {
	const matches = useMatches();
	const lastMatch = matches[matches.length - 1];
	const lastUpdated = (lastMatch?.handle as { lastUpdated?: string } | undefined)?.lastUpdated;

	return (
		<div className="flex min-h-screen flex-col">
			<header className="sticky top-0 z-50 border-b border-border bg-background/80 backdrop-blur-sm">
				<div className="mx-auto flex h-14 max-w-5xl items-center justify-between px-6">
					<div className="flex items-center gap-6">
						<Link to="/" className="font-heading text-lg font-bold tracking-tight">
							@oidfed
						</Link>
						<nav className="hidden items-center gap-4 text-sm sm:flex">
							<Link
								to="/ecosystem"
								className="text-muted-foreground hover:text-foreground transition-colors"
							>
								Ecosystem
							</Link>
							<Link
								to="/about"
								className="text-muted-foreground hover:text-foreground transition-colors"
							>
								About
							</Link>
						</nav>
					</div>
					<div className="flex items-center gap-2">
						<nav className="hidden items-center gap-3 text-sm sm:flex">
							<a
								href="https://explore.oidfed.com"
								target="_blank"
								rel="noopener noreferrer"
								className="flex items-center gap-1 text-muted-foreground hover:text-foreground transition-colors"
							>
								Explorer <ExternalLink className="size-3" />
							</a>
							<a
								href="https://learn.oidfed.com"
								target="_blank"
								rel="noopener noreferrer"
								className="flex items-center gap-1 text-muted-foreground hover:text-foreground transition-colors"
							>
								Learn <ExternalLink className="size-3" />
							</a>
							<a
								href="https://github.com/Dahkenangnon/oidfed"
								target="_blank"
								rel="noopener noreferrer"
								className="flex items-center gap-1 text-muted-foreground hover:text-foreground transition-colors"
							>
								GitHub <ExternalLink className="size-3" />
							</a>
						</nav>
						<ThemeToggle />
					</div>
				</div>
			</header>

			<main className="flex-1">
				<Outlet />
			</main>

			<footer className="border-t border-border py-8">
				<div className="mx-auto max-w-5xl px-6">
					<div className="flex flex-col items-center justify-between gap-4 sm:flex-row">
						<p className="text-sm text-muted-foreground">
							@oidfed — OpenID Federation 1.0 for JavaScript, runtime-agnostic
						</p>
						<div className="flex items-center gap-4 text-sm text-muted-foreground">
							{lastUpdated && <span>Last reviewed: {lastUpdated}</span>}
							<a
								href="https://github.com/Dahkenangnon/oidfed"
								target="_blank"
								rel="noopener noreferrer"
								className="hover:text-foreground transition-colors"
							>
								GitHub
							</a>
							<a
								href="https://www.npmjs.com/org/oidfed"
								target="_blank"
								rel="noopener noreferrer"
								className="hover:text-foreground transition-colors"
							>
								npm
							</a>
						</div>
					</div>
				</div>
			</footer>
		</div>
	);
}
