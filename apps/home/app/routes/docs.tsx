import { ArrowUpRight, ChevronRight } from "lucide-react";
import { isRouteErrorResponse, Link, NavLink } from "react-router";
import { guideCatalog, renderDocumentation } from "../lib/docs.server";
import { buildMeta, DOMAIN } from "../lib/seo";
import type { Route } from "./+types/docs";
import "./docs.css";

const sections = [
	["API reference", "/docs/api"],
	["@oidfed/core", "/docs/api/core"],
	["@oidfed/crypto", "/docs/api/crypto"],
	["@oidfed/authority", "/docs/api/authority"],
	["@oidfed/leaf", "/docs/api/leaf"],
	["@oidfed/oidc", "/docs/api/oidc"],
	["@oidfed/wallet", "/docs/api/wallet"],
	["Migrate to v3", "/docs/api/migration-v3"],
	["React Native", "/docs/api/react-native"],
	["Development", "/docs/maintenance/development"],
] as const;

const featureIndex = "/docs/features";

export function loader({ params }: Route.LoaderArgs) {
	const path = params["*"] ? `/docs/${params["*"].replace(/\/$/, "")}` : "/docs";
	const page = renderDocumentation(path);
	if (!page) throw new Response("Documentation page not found", { status: 404 });
	return { ...page, path, topics: guideCatalog };
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
	const { headings, html, path, source, topics } = loaderData;
	return (
		<div className="docs-layout mx-auto max-w-7xl px-5 py-10 sm:px-8 sm:py-14">
			<details key={path} className="docs-sidebar" open={path === featureIndex}>
				<summary>Documentation menu</summary>
				<DocumentationNav path={path} topics={topics} />
			</details>
			<aside className="docs-sidebar-desktop">
				<DocumentationNav key={path} path={path} topics={topics} />
			</aside>
			<div className="min-w-0">
				{/* biome-ignore lint/security/noDangerouslySetInnerHtml: server-only Markdown rendering escapes raw HTML and validates URLs */}
				<article className="docs-article" dangerouslySetInnerHTML={{ __html: html }} />
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

function DocumentationNav({
	path,
	topics,
}: {
	path: string;
	topics: Route.ComponentProps["loaderData"]["topics"];
}) {
	return (
		<nav aria-label="Documentation">
			<ul className="space-y-1">
				<li>
					<DocumentationLink href="/docs" label="Documentation home" />
				</li>
				<li>
					<details
						className="docs-nav-branch"
						open={path === featureIndex || path.startsWith(`${featureIndex}/`)}
					>
						<summary>
							<ChevronRight aria-hidden /> Feature guides
						</summary>
						<ul>
							<li>
								<DocumentationLink href={featureIndex} label="All feature guides" />
							</li>
							{topics.map((topic) => (
								<li key={topic.path}>
									{topic.guides.length === 0 ? (
										<DocumentationLink href={topic.path} label={topic.label} />
									) : (
										<details
											className="docs-nav-branch"
											open={
												path === topic.path || topic.guides.some((guide) => guide.path === path)
											}
										>
											<summary>
												<ChevronRight aria-hidden /> {topic.label}
											</summary>
											<ul>
												<li>
													<DocumentationLink
														href={topic.path}
														label="Topic overview"
														accessibleLabel={`${topic.label} overview`}
													/>
												</li>
												{topic.guides.map((guide) => (
													<li key={guide.path}>
														<DocumentationLink href={guide.path} label={guide.label} />
													</li>
												))}
											</ul>
										</details>
									)}
								</li>
							))}
						</ul>
					</details>
				</li>
				{sections.map(([label, href]) => (
					<li key={href}>
						<DocumentationLink href={href} label={label} end={!href.startsWith("/docs/api/")} />
					</li>
				))}
			</ul>
		</nav>
	);
}

function DocumentationLink({
	href,
	label,
	accessibleLabel,
	end = true,
}: {
	href: string;
	label: string;
	accessibleLabel?: string;
	end?: boolean;
}) {
	return (
		<NavLink to={href} end={end} aria-label={accessibleLabel} className="docs-nav-link">
			{label}
		</NavLink>
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
