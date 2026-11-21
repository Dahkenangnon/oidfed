import { GitHubIcon, OidfedLogo } from "@oidfed/ui";
import { ArrowRight, Menu, X } from "lucide-react";
import { useEffect, useId, useState } from "react";
import { Link, NavLink, Outlet, useLocation } from "react-router";
import { InstallCommand } from "../components/copy-button";
import { ThemeToggle } from "../components/theme-toggle";
import { DOCS, EXPLORER, FEDERATIONS, LEARN, REPOSITORY } from "../lib/links";

const primaryLinks = [
	{ label: "Docs", href: DOCS },
	{ label: "Learn", href: LEARN },
	{ label: "Explorer", href: EXPLORER },
	{ label: "Ecosystem", href: "/ecosystem" },
];

const footerGroups = [
	{
		label: "Build",
		links: [
			{ label: "Quickstart", href: "/#quickstart" },
			{ label: "API reference", href: `${DOCS}/api` },
			{ label: "Migrate to v3", href: `${DOCS}/api/migration-v3` },
			{ label: "React Native", href: `${DOCS}/api/react-native` },
		],
	},
	{
		label: "Explore",
		links: [
			{ label: "Learn OpenID Federation", href: LEARN },
			{ label: "Trust-chain Explorer", href: EXPLORER },
			{ label: "Demo federations", href: FEDERATIONS },
			{ label: "Trust Journal", href: "/trust-journal" },
		],
	},
	{
		label: "Standards",
		links: [
			{ label: "Ecosystem", href: "/ecosystem" },
			{
				label: "OpenID Federation 1.1",
				href: "https://openid.net/specs/openid-federation-1_1-final.html",
			},
			{
				label: "OpenID Connect profile",
				href: "https://openid.net/specs/openid-federation-connect-1_1-final.html",
			},
		],
	},
	{
		label: "Project",
		links: [
			{ label: "About OidFed", href: "/about" },
			{ label: "Contributing", href: `${REPOSITORY}/blob/main/CONTRIBUTING.md` },
			{ label: "Security", href: `${REPOSITORY}/blob/main/SECURITY.md` },
		],
	},
];

export default function SiteLayout() {
	return (
		<div className="flex min-h-screen flex-col">
			<a
				href="#main-content"
				className="sr-only focus:not-sr-only focus:absolute focus:z-10 focus:m-2 focus:rounded-md focus:bg-background focus:p-3 focus:font-semibold"
			>
				Skip to content
			</a>
			<SiteHeader />
			<main id="main-content" tabIndex={-1} className="flex-1">
				<Outlet />
			</main>
			<SiteFooter />
		</div>
	);
}

function SiteHeader() {
	const location = useLocation();
	const menuId = useId();
	const [open, setOpen] = useState(false);

	useEffect(() => {
		setOpen(false);
	}, [location.key]);

	return (
		<header>
			<Link
				to="/trust-journal#standards"
				className="site-announcement flex items-center justify-center gap-2 px-4 py-2 text-center text-sm font-medium hover:underline"
			>
				<span>Wallet and Entity Collection draft updates</span>
				<ArrowRight aria-hidden className="size-3.5 shrink-0" />
			</Link>
			<div className="border-b border-border">
				<div className="mx-auto flex min-h-16 max-w-6xl items-center justify-between gap-5 px-5 sm:px-8">
					<Link to="/" aria-label="OidFed home" className="shrink-0">
						<OidfedLogo label="oidfed" markClassName="size-8" labelClassName="text-lg" />
					</Link>

					<nav aria-label="Primary" className="hidden items-center gap-5 lg:flex xl:gap-7">
						<PrimaryLinks />
					</nav>

					<div className="flex shrink-0 items-center gap-2">
						<Link
							to="/#quickstart"
							className="site-button hidden min-h-9 px-4 lg:inline-flex"
						>
							Get started
						</Link>
						<a
							href={REPOSITORY}
							aria-label="OidFed on GitHub"
							className="grid size-9 place-items-center rounded-md text-foreground hover:bg-muted"
						>
							<GitHubIcon aria-hidden className="size-5" />
						</a>
						<ThemeToggle />
						<button
							type="button"
							className="grid size-9 place-items-center rounded-md border border-border lg:hidden"
							aria-label={open ? "Close navigation menu" : "Open navigation menu"}
							aria-expanded={open}
							aria-controls={menuId}
							onClick={() => setOpen(!open)}
						>
							{open ? (
								<X aria-hidden className="size-4" />
							) : (
								<Menu aria-hidden className="size-4" />
							)}
						</button>
					</div>
				</div>

				<nav
					id={menuId}
					aria-label="Primary mobile navigation"
					className={`mx-auto max-w-6xl flex-col gap-1 border-t border-border px-5 py-3 sm:px-8 lg:hidden ${open ? "flex" : "hidden"}`}
				>
					<PrimaryLinks mobile />
					<Link to="/#quickstart" className="site-button mt-2 w-full">
						Get started
					</Link>
				</nav>
			</div>
		</header>
	);
}

function PrimaryLinks({ mobile = false }: { mobile?: boolean }) {
	const style = mobile
		? "block rounded-md px-3 py-2.5 text-sm font-medium hover:bg-muted aria-[current=page]:text-site-accent"
		: "text-sm font-medium hover:text-site-accent aria-[current=page]:text-site-accent aria-[current=page]:underline underline-offset-6";

	return primaryLinks.map(({ label, href }) =>
		href.startsWith("/") ? (
			<NavLink key={href} to={href} className={style}>
				{label}
			</NavLink>
		) : (
			<a key={href} href={href} className={style}>
				{label}
			</a>
		),
	);
}

function SiteFooter() {
	return (
		<footer className="site-footer">
			<div className="relative mx-auto max-w-6xl px-5 pt-12 pb-4 sm:px-8 sm:pt-16">
				<div className="grid gap-10 md:gap-12">
					<div className="flex min-w-0 flex-col items-center text-center">
						<Link
							to="/docs"
							className="site-footer-cta inline-flex items-center gap-2 text-base font-semibold"
						>
							Start building <ArrowRight aria-hidden className="size-4" />
						</Link>
						<div className="mt-5">
							<InstallCommand label="Core install command from footer" />
						</div>
					</div>
					<nav
						aria-label="Footer"
						className="grid grid-cols-2 items-start gap-x-5 gap-y-8 text-center sm:grid-cols-4"
					>
						{footerGroups.map(({ label, links }) => (
							<div key={label}>
								<h2 className="mb-3 text-sm font-semibold">{label}</h2>
								<ul className="space-y-2.5 text-sm text-muted-foreground">
									{links.map(({ label, href }) => (
										<li key={href}>
											{href.startsWith("/") ? (
												<Link to={href} className="hover:text-foreground hover:underline">
													{label}
												</Link>
											) : (
												<a href={href} className="hover:text-foreground hover:underline">
													{label}
												</a>
											)}
										</li>
									))}
								</ul>
							</div>
						))}
					</nav>
				</div>
				<div className="site-footer-signature text-center">
					<Link to="/" aria-label="OidFed home" className="site-footer-wordmark">
						OidFed
					</Link>
				</div>
				<div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 border-t border-border pt-3">
					<p className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground sm:text-sm">
						<span>© 2026 Yamonwan Justin Dah-kenangnon</span>
						<a className="site-link" href={`${REPOSITORY}/blob/main/LICENSE`}>
							Libraries: Apache-2.0
						</a>
						<a className="site-link" href={`${REPOSITORY}/blob/main/apps/home/LICENSE`}>
							This site: MIT
						</a>
					</p>
					<a
						href={REPOSITORY}
						aria-label="OidFed on GitHub"
						className="site-footer-cta inline-flex items-center gap-2 text-sm font-semibold"
					>
						<GitHubIcon className="size-4" /> GitHub
					</a>
				</div>
			</div>
		</footer>
	);
}
