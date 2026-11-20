import { ArrowUpRight, ChevronRight } from "lucide-react";
import { useEffect, useRef } from "react";
import { isRouteErrorResponse, Link, useLocation } from "react-router";
import { DocsArticle } from "../components/docs-article";
import { guideCatalog, packagePages, renderDocumentation } from "../lib/docs.server";
import { buildMeta, DOMAIN } from "../lib/seo";
import type { Route } from "./+types/docs";
import "./docs.css";

const packages = [
	["Core", "/docs/api/core"],
	["Crypto", "/docs/api/crypto"],
	["Authority", "/docs/api/authority"],
	["Leaf", "/docs/api/leaf"],
	["OIDC", "/docs/api/oidc"],
	["Wallet", "/docs/api/wallet"],
] as const;

const featureIndex = "/docs/features";
type DocsNavigation = Pick<Route.ComponentProps["loaderData"], "path" | "topics" | "apiPages">;

export function loader({ params }: Route.LoaderArgs) {
	const path = params["*"] ? `/docs/${params["*"].replace(/\/$/, "")}` : "/docs";
	const page = renderDocumentation(path);
	if (!page) throw new Response("Documentation page not found", { status: 404 });
	return { ...page, path, topics: guideCatalog, apiPages: packagePages };
}

export function meta({ loaderData }: Route.MetaArgs) {
	if (!loaderData) {
		return buildMeta({
			title: "Documentation page not found | OidFed",
			description: "Browse the OidFed documentation to find a guide or API reference.",
			path: "/docs",
			noindex: true,
		});
	}
	const { title, description, path } = loaderData;
	const packageName = path.match(
		/^\/docs\/api\/(core|crypto|authority|leaf|oidc|wallet)(?:\/|$)/,
	)?.[1];
	const section = packageName ? `@oidfed/${packageName}` : "OidFed Documentation";
	return buildMeta({
		title:
			path === "/docs"
				? "OpenID Federation Documentation & API Reference | OidFed"
				: `${title} | ${section}`,
		description,
		path,
		ogType: "article",
		jsonLd: {
			"@context": "https://schema.org",
			"@type": "TechArticle",
			headline: title,
			description,
			url: `${DOMAIN}${path}`,
			inLanguage: "en",
			isPartOf: { "@id": `${DOMAIN}/#website` },
			publisher: { "@id": `${DOMAIN}/#organization` },
		},
	});
}

export default function Documentation({ loaderData }: Route.ComponentProps) {
	const { headings, html, path, source, topics, apiPages } = loaderData;
	const sidebar = useRef<HTMLElement>(null);

	useEffect(() => {
		const rail = sidebar.current;
		const active = rail?.querySelector('[aria-current="page"]');
		if (!rail || !active || !rail.clientHeight) return;
		const railBounds = rail.getBoundingClientRect();
		const linkBounds = active.getBoundingClientRect();
		if (linkBounds.top < railBounds.top || linkBounds.bottom > railBounds.bottom) {
			rail.scrollTop += linkBounds.top - railBounds.top - rail.clientHeight / 2;
		}
	}, [path]);

	return (
		<div className="docs-layout mx-auto max-w-7xl px-5 py-10 sm:px-8 sm:py-14">
			<details key={path} className="docs-sidebar" open={path === featureIndex}>
				<summary>Documentation menu</summary>
				<DocumentationNav path={path} topics={topics} apiPages={apiPages} />
			</details>
			<aside ref={sidebar} className="docs-sidebar-desktop">
				<DocumentationNav key={path} path={path} topics={topics} apiPages={apiPages} />
			</aside>
			<div className="min-w-0">
				<DocsArticle html={html} />
				<a href={source} className="site-link mt-10 inline-flex items-center gap-1.5 text-sm">
					View source on GitHub <ArrowUpRight aria-hidden className="size-3.5" />
				</a>
			</div>
			{headings.length > 0 && (
				<nav aria-label="On this page" className="docs-outline">
					<p className="mb-3 text-sm font-semibold">On this page</p>
					<ul className="space-y-2 text-sm text-muted-foreground">
						{headings.map(({ id, label, level }) => (
							<li key={id} className={level === 3 ? "pl-3" : undefined}>
								<a href={`#${id}`} className="wrap-anywhere hover:text-site-accent hover:underline">
									{label}
								</a>
							</li>
						))}
					</ul>
				</nav>
			)}
		</div>
	);
}

function DocumentationNav({ path, topics, apiPages }: DocsNavigation) {
	return (
		<nav aria-label="Documentation" className="docs-nav">
			<section aria-label="Get started">
				<h2 className="docs-nav-heading">Get started</h2>
				<ul>
					<li>
						<DocumentationLink href="/docs" label="Overview" />
					</li>
					<li>
						<DocumentationLink href="/docs/api/migration-v3" label="Migrate to v3" />
					</li>
					<li>
						<DocumentationLink href="/docs/api/react-native" label="React Native" />
					</li>
				</ul>
			</section>
			<section aria-label="Feature guides">
				<details
					className="docs-nav-branch docs-nav-section"
					open={path === featureIndex || path.startsWith(`${featureIndex}/`)}
				>
					<summary className="docs-nav-heading">
						Feature guides <ChevronRight aria-hidden />
					</summary>
					<ul>
						<li>
							<DocumentationLink href={featureIndex} label="Guide index" />
						</li>
						{topics.map((topic) => {
							const label = guideLabel(topic.label);
							const current =
								path === topic.path || topic.guides.some((guide) => guide.path === path);
							return (
								<li key={topic.path}>
									{topic.guides.length === 0 ? (
										<DocumentationLink href={topic.path} label={label} />
									) : (
										<details
											className="docs-nav-branch"
											open={current}
											data-current={current || undefined}
										>
											<summary>
												<span>{label}</span> <ChevronRight aria-hidden />
											</summary>
											<ul>
												<li>
													<DocumentationLink
														href={topic.path}
														label="Overview"
														accessibleLabel={`${label} overview`}
													/>
												</li>
												{topic.guides.map((guide) => (
													<li key={guide.path}>
														<DocumentationLink href={guide.path} label={guideLabel(guide.label)} />
													</li>
												))}
											</ul>
										</details>
									)}
								</li>
							);
						})}
					</ul>
				</details>
			</section>
			<section aria-label="API reference">
				<h2 className="docs-nav-heading">API reference</h2>
				<ul>
					<li>
						<DocumentationLink href="/docs/api" label="API index" />
					</li>
					{packages.map(([label, href]) => {
						const pages = apiPages.filter((page) => page.path.startsWith(`${href}/`));
						const current = path === href || pages.some((page) => page.path === path);
						return (
							<li key={href} className="docs-nav-package" data-current={current || undefined}>
								<DocumentationLink href={href} label={label} />
								{pages.length > 0 && (
									<details className="docs-nav-branch" open={current}>
										<summary aria-label={`${label} reference pages`}>
											<ChevronRight aria-hidden />
										</summary>
										<ul>
											{pages.map((page) => (
												<li key={page.path}>
													<DocumentationLink href={page.path} label={page.label} />
												</li>
											))}
										</ul>
									</details>
								)}
							</li>
						);
					})}
				</ul>
			</section>
			<section aria-label="Maintenance">
				<h2 className="docs-nav-heading">Maintenance</h2>
				<ul>
					<li>
						<DocumentationLink href="/docs/maintenance/development" label="Development" />
					</li>
					<li>
						<DocumentationLink href="/docs/maintenance/security-checks" label="Security checks" />
					</li>
					<li>
						<DocumentationLink href="/docs/maintenance/releases" label="Releases" />
					</li>
				</ul>
			</section>
		</nav>
	);
}

function guideLabel(title: string) {
	return title.replace(/^\d+(?:\.\d+)*\.\s+/, "");
}

function DocumentationLink({
	href,
	label,
	accessibleLabel,
}: {
	href: string;
	label: string;
	accessibleLabel?: string;
}) {
	const current = useLocation().pathname.replace(/\/$/, "") === href;
	return (
		<Link
			to={href}
			aria-current={current ? "page" : undefined}
			aria-label={accessibleLabel}
			className="docs-nav-link"
		>
			{label}
		</Link>
	);
}

export function ErrorBoundary({ error }: Route.ErrorBoundaryProps) {
	const missing = isRouteErrorResponse(error) && error.status === 404;
	return (
		<section className="mx-auto max-w-3xl px-5 py-20 sm:px-8">
			<h1 className="site-section-title">
				{missing ? "Documentation page not found" : "Unable to load documentation"}
			</h1>
			<Link to="/docs" className="site-link mt-5 inline-block">
				Back to documentation
			</Link>
		</section>
	);
}
