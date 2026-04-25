import { ArrowUpRight } from "lucide-react";
import { Link, Outlet, useLocation } from "react-router";
import { ThemeToggle } from "../components/theme-toggle";

const NAV_PRIMARY = [
	{ to: "/", label: "Home" },
	{ to: "/ecosystem", label: "Ecosystem" },
	{ to: "/about", label: "About" },
];

const NAV_EXTERNAL = [
	{ href: "https://explore.oidfed.com", label: "Explorer" },
	{ href: "https://learn.oidfed.com", label: "Learn" },
	{ href: "https://github.com/Dahkenangnon/oidfed", label: "GitHub" },
];

export default function SiteLayout() {
	return (
		<div className="flex min-h-screen flex-col">
			<SiteHeader />
			<main className="flex-1">
				<Outlet />
			</main>
			<SiteFooter />
		</div>
	);
}

// ─────────────────────────────────────────────────────────────────────────────
// Header (unchanged from previous redesign)
// ─────────────────────────────────────────────────────────────────────────────

function SiteHeader() {
	const location = useLocation();
	return (
		<header className="sticky top-0 z-50 border-b border-border/60 bg-background/80 backdrop-blur-md supports-[backdrop-filter]:bg-background/60">
			<div className="mx-auto flex h-14 max-w-6xl items-center gap-4 px-4 sm:gap-6 sm:px-6">
				<Link to="/" className="group flex items-center gap-2" aria-label="@oidfed — home">
					<span aria-hidden className="relative inline-flex size-6 items-center justify-center">
						<span className="absolute inset-0 rounded-md bg-brand-500/15 transition-colors group-hover:bg-brand-500/25" />
						<span className="relative font-mono text-[13px] font-bold text-brand-500">@</span>
					</span>
					<span className="font-heading text-[15px] font-semibold tracking-tight">oidfed</span>
					<span
						aria-hidden
						className="ml-1 hidden font-mono text-[9.5px] font-semibold uppercase tracking-[0.22em] text-muted-foreground sm:inline"
					>
						v0.1.0
					</span>
				</Link>

				<span aria-hidden className="h-5 w-px bg-border/70" />

				<nav className="flex min-w-0 items-center gap-1">
					{NAV_PRIMARY.filter((n) => n.to !== "/").map((item) => {
						const active = location.pathname === item.to;
						return (
							<Link
								key={item.to}
								to={item.to}
								className={`relative rounded-md px-2.5 py-1 text-[13px] transition-colors ${
									active ? "text-foreground" : "text-muted-foreground hover:text-foreground"
								}`}
								aria-current={active ? "page" : undefined}
							>
								{item.label}
								{active && (
									<span
										aria-hidden
										className="absolute inset-x-2.5 -bottom-[11px] h-px bg-brand-500"
									/>
								)}
							</Link>
						);
					})}
				</nav>

				<div className="ml-auto flex items-center gap-1 sm:gap-2">
					<nav className="hidden items-center gap-1 md:flex">
						{NAV_EXTERNAL.map((item) => (
							<a
								key={item.href}
								href={item.href}
								target="_blank"
								rel="noopener noreferrer"
								className="group flex items-center gap-1 rounded-md px-2.5 py-1 text-[13px] text-muted-foreground transition-colors hover:text-foreground"
							>
								{item.label}
								<ArrowUpRight className="size-3 transition-transform group-hover:-translate-y-0.5 group-hover:translate-x-0.5" />
							</a>
						))}
					</nav>
					<a
						href="https://explore.oidfed.com"
						target="_blank"
						rel="noopener noreferrer"
						className="inline-flex h-8 items-center gap-1 rounded-md border border-border bg-background px-2.5 text-[12px] font-medium text-foreground transition-colors hover:border-foreground/30 md:hidden"
					>
						Explorer <ArrowUpRight className="size-3" />
					</a>
					<ThemeToggle />
				</div>
			</div>
		</header>
	);
}

// ─────────────────────────────────────────────────────────────────────────────
// Footer — minimal © line
// ─────────────────────────────────────────────────────────────────────────────

function SiteFooter() {
	return (
		<footer className="relative border-t border-border/60 bg-muted/20">
			<div
				aria-hidden
				className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-brand-500/40 to-transparent"
			/>
			<div className="mx-auto flex max-w-6xl flex-col items-center justify-between gap-3 px-6 py-6 text-[12px] text-muted-foreground/80 sm:flex-row">
				<Link to="/" className="flex items-center gap-2 transition-colors hover:text-foreground">
					<span aria-hidden className="relative inline-flex size-5 items-center justify-center">
						<span className="absolute inset-0 rounded-md bg-brand-500/15" />
						<span className="relative font-mono text-[11px] font-bold text-brand-500">@</span>
					</span>
					<span className="font-heading text-[13px] font-medium tracking-tight text-foreground">
						oidfed
					</span>
				</Link>
				<p className="font-mono text-[11px] tracking-wide">
					© 2026{" "}
					<a
						href="https://github.com/Dahkenangnon"
						target="_blank"
						rel="noopener noreferrer"
						className="transition-colors hover:text-foreground"
					>
						Justin Dah-kenangnon
					</a>
				</p>
				<a
					href="https://openid.net/specs/openid-federation-1_0.html"
					target="_blank"
					rel="noopener noreferrer"
					className="group inline-flex items-center gap-1 font-mono text-[10.5px] uppercase tracking-[0.18em] transition-colors hover:text-foreground"
				>
					OpenID Federation 1.0 spec
					<ArrowUpRight className="size-3 transition-transform group-hover:-translate-y-0.5 group-hover:translate-x-0.5" />
				</a>
			</div>
		</footer>
	);
}
