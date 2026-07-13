import { OidfedLogo } from "@oidfed/ui";
import { ArrowUpRight, Menu, X } from "lucide-react";
import { useEffect, useId, useRef, useState } from "react";
import { Link, Outlet, useLocation } from "react-router";
import { ThemeToggle } from "../components/theme-toggle";

const NAV_PRIMARY = [
	{ to: "/", label: "Home" },
	{ to: "/ecosystem", label: "Ecosystem" },
	{ to: "/about", label: "About" },
];

const NAV_EXTERNAL = [
	{ href: "https://explore.oidfed.com", label: "Explorer" },
	{ href: "https://fed.oidfed.com", label: "Federations" },
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
// Header
// ─────────────────────────────────────────────────────────────────────────────

function SiteHeader() {
	const location = useLocation();
	const mobileMenuId = useId();
	const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
	const previousPathname = useRef(location.pathname);

	useEffect(() => {
		if (previousPathname.current === location.pathname) return;
		previousPathname.current = location.pathname;
		setMobileMenuOpen(false);
	}, [location.pathname]);

	const isActive = (to: string) => location.pathname === to;

	return (
		<header className="sticky top-0 z-50 border-b border-border/60 bg-background/80 backdrop-blur-md supports-[backdrop-filter]:bg-background/60">
			<div className="mx-auto flex h-14 max-w-6xl items-center gap-3 px-4 sm:gap-5 sm:px-6">
				<Link
					to="/"
					className="group flex min-w-0 items-center gap-2"
					aria-label="@oidfed — home"
				>
					<OidfedLogo
						label="oidfed"
						markClassName="size-7 transition-transform group-hover:scale-105"
					/>
				</Link>

				<span aria-hidden className="hidden h-5 w-px bg-border/70 md:block" />

				<nav className="hidden min-w-0 items-center gap-1 md:flex" aria-label="Primary">
					{NAV_PRIMARY.filter((n) => n.to !== "/").map((item) => {
						const active = isActive(item.to);
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
					<nav className="hidden items-center gap-1 lg:flex" aria-label="External">
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
					<ThemeToggle />
					<button
						type="button"
						className="inline-flex size-9 items-center justify-center rounded-md border border-border bg-background text-muted-foreground transition-colors hover:border-foreground/30 hover:text-foreground lg:hidden"
						aria-label={mobileMenuOpen ? "Close navigation menu" : "Open navigation menu"}
						aria-controls={mobileMenuId}
						aria-expanded={mobileMenuOpen}
						onClick={() => setMobileMenuOpen((open) => !open)}
					>
						{mobileMenuOpen ? <X className="size-4" /> : <Menu className="size-4" />}
					</button>
				</div>
			</div>

			<div
				id={mobileMenuId}
				className={`${mobileMenuOpen ? "block" : "hidden"} border-t border-border/60 bg-background/95 shadow-sm lg:hidden`}
			>
				<div className="mx-auto grid max-w-6xl gap-4 px-4 py-4 sm:px-6 md:grid-cols-2">
					<nav aria-label="Primary mobile navigation" className="grid gap-1">
						<p className="px-2 font-mono text-[10px] uppercase tracking-[0.18em] text-muted-foreground">
							Pages
						</p>
						{NAV_PRIMARY.map((item) => {
							const active = isActive(item.to);
							return (
								<Link
									key={item.to}
									to={item.to}
									className={`flex h-10 items-center rounded-md px-2.5 text-[14px] transition-colors ${
										active
											? "bg-brand-500/10 text-foreground"
											: "text-muted-foreground hover:bg-muted hover:text-foreground"
									}`}
									aria-current={active ? "page" : undefined}
									onClick={() => setMobileMenuOpen(false)}
								>
									{item.label}
								</Link>
							);
						})}
					</nav>

					<nav aria-label="External mobile navigation" className="grid gap-1">
						<p className="px-2 font-mono text-[10px] uppercase tracking-[0.18em] text-muted-foreground">
							Tools
						</p>
						{NAV_EXTERNAL.map((item) => (
							<a
								key={item.href}
								href={item.href}
								target="_blank"
								rel="noopener noreferrer"
								className="group flex h-10 items-center justify-between rounded-md px-2.5 text-[14px] text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
								onClick={() => setMobileMenuOpen(false)}
							>
								<span>{item.label}</span>
								<ArrowUpRight className="size-3.5 transition-transform group-hover:-translate-y-0.5 group-hover:translate-x-0.5" />
							</a>
						))}
					</nav>
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
					<OidfedLogo label="oidfed" markClassName="size-6" labelClassName="text-[13px]" />
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
