import { Badge, Button, Card, CardContent, CardHeader, CardTitle } from "@oidfed/ui";
import {
	BadgeCheck,
	Clock,
	ExternalLink,
	FileSearch,
	FlaskConical,
	GitCompare,
	Globe,
	HeartPulse,
	Link,
	List,
	Route,
} from "lucide-react";
import { useNavigate } from "react-router";
import { usePageTitle } from "@/hooks/use-page-title";

const packages = [
	{
		name: "@oidfed/core",
		role: "Federation primitives — entity statements, trust chain resolution, metadata policy, and cryptographic verification",
		category: "package",
	},
	{
		name: "@oidfed/authority",
		role: "Trust Anchor and Intermediate Authority operations — subordinate management, statement issuance, federation endpoint serving, and policy enforcement",
		category: "package",
	},
	{
		name: "@oidfed/leaf",
		role: "Leaf Entity toolkit — Entity Configuration serving, authority discovery, and trust chain participation",
		category: "package",
	},
	{
		name: "@oidfed/oidc",
		role: "OpenID Connect and OAuth 2.0 federation flows — automatic and explicit client registration, Request Object validation, and RP/OP metadata processing",
		category: "package",
	},
	{
		name: "@oidfed/cli",
		role: "Command-line interface for inspecting, validating, and debugging OpenID Federation deployments",
		category: "tool",
	},
	{
		name: "@oidfed/explorer",
		role: "Visual tool for exploring live OpenID Federation deployments (you are here)",
		category: "app",
		url: "https://explore.oidfed.com",
	},
	{
		name: "@oidfed/home",
		role: "The official home of @oidfed — project documentation and resources",
		category: "app",
		url: "https://oidfed.com",
	},
	{
		name: "@oidfed/learn",
		role: "An interactive course on OpenID Federation 1.0 — 15 lessons from first principles to federation topology design",
		category: "app",
		url: "https://learn.oidfed.com",
	},
] as const;

const features = [
	{
		icon: FileSearch,
		name: "Entity Inspector",
		path: "/entity",
		description: "Fetch and decode any entity configuration with JWT viewer and JWKS table",
	},
	{
		icon: Link,
		name: "Trust Chain",
		path: "/chain",
		description: "Resolve and visualize trust chains with signature verification per link",
	},
	{
		icon: Globe,
		name: "Topology Graph",
		path: "/topology",
		description: "Interactive federation graph with auto-expand and right-click context menu",
	},
	{
		icon: List,
		name: "Subordinates",
		path: "/subordinates",
		description: "Browse and filter subordinates of any authority",
	},
	{
		icon: Clock,
		name: "Expiration Dashboard",
		path: "/expiry",
		description: "Monitor trust chain expirations with color-coded timeline",
	},
	{
		icon: BadgeCheck,
		name: "Trust Marks",
		path: "/trust-marks",
		description: "Inspect, verify, and trace trust mark delegation chains",
	},
	{
		icon: FlaskConical,
		name: "Policy Simulator",
		path: "/policy",
		description: "Apply and compose metadata policies with conflict detection",
	},
	{
		icon: HeartPulse,
		name: "Health Check",
		path: "/health",
		description: "Probe federation endpoints for availability and correctness",
	},
	{
		icon: Route,
		name: "Resolve Proxy",
		path: "/resolve",
		description: "Query any entity's resolve endpoint and compare results",
	},
	{
		icon: GitCompare,
		name: "Metadata Diff",
		path: "/diff",
		description: "Compare resolved metadata across trust anchors or policy levels",
	},
] as const;

export function HomePage() {
	usePageTitle("OidFed Explorer");
	const navigate = useNavigate();

	return (
		<div className="space-y-12 py-8">
			{/* Hero */}
			<section className="relative overflow-hidden rounded-xl border bg-gradient-to-br from-brand-50 via-white to-brand-100 px-6 py-16 text-center dark:from-brand-900/20 dark:via-background dark:to-brand-800/10">
				{/* Dot-grid background pattern */}
				<svg
					aria-hidden="true"
					className="pointer-events-none absolute inset-0 -z-10 h-full w-full text-brand-500 opacity-[0.12] dark:opacity-[0.06]"
				>
					<defs>
						<pattern id="dot-grid" x="0" y="0" width="20" height="20" patternUnits="userSpaceOnUse">
							<circle cx="2" cy="2" r="1.2" fill="currentColor" />
						</pattern>
					</defs>
					<rect width="100%" height="100%" fill="url(#dot-grid)" />
				</svg>
				{/* Radial glow accent */}
				<div className="pointer-events-none absolute left-1/2 top-0 -z-10 h-64 w-[32rem] -translate-x-1/2 rounded-full bg-brand-400/20 blur-3xl dark:bg-brand-500/10" />
				<div className="space-y-4">
					<h1 className="text-4xl font-bold tracking-tight sm:text-5xl">
						<span className="text-brand-600 dark:text-brand-400">OidFed</span> Explorer
					</h1>
					<p className="mx-auto max-w-2xl text-muted-foreground">
						An interactive companion for OpenID Federation 1.0 — inspect, resolve, visualize, and
						debug federation entities directly in your browser. No backend required.
					</p>
					<div className="flex flex-wrap justify-center gap-3 pt-2">
						<Button onClick={() => navigate("/entity")}>Open Entity Inspector</Button>
						<Button
							variant="outline"
							render={
								<a
									href="https://github.com/Dahkenangnon/oidfed"
									target="_blank"
									rel="noopener noreferrer"
									aria-label="View OidFed on GitHub"
								/>
							}
						>
							<ExternalLink className="mr-2 size-4" />
							View on GitHub
						</Button>
					</div>
				</div>
			</section>

			{/* About the project */}
			<section className="space-y-4">
				<h2 className="text-2xl font-semibold tracking-tight">About the project</h2>
				<p className="text-muted-foreground">
					The complete OpenID Federation 1.0 implementation for JavaScript — runtime-agnostic,
					spec-compliant, built on Web API standards.
				</p>
				<div className="space-y-6">
					{(["package", "tool", "app"] as const).map((category) => {
						const items = packages.filter((pkg) => pkg.category === category);
						const title =
							category === "package" ? "Packages" : category === "tool" ? "Tools" : "Apps";
						return (
							<div key={category}>
								<h3 className="mb-2 text-center text-sm font-semibold uppercase tracking-wider text-muted-foreground">
									{title}
								</h3>
								<div className="overflow-x-auto rounded-xl border bg-card shadow-xs">
									<table className="w-full text-sm">
										<thead>
											<tr className="border-b bg-brand-50/80 dark:bg-brand-900/30">
												<th className="px-4 py-2 text-left font-medium">Package</th>
												<th className="px-4 py-2 text-left font-medium">Role</th>
												{category === "app" && (
													<th className="px-4 py-2 text-left font-medium">Link</th>
												)}
											</tr>
										</thead>
										<tbody>
											{items.map((pkg, i) => (
												<tr
													key={pkg.name}
													className={`${i < items.length - 1 ? "border-b" : ""} hover:bg-muted/50 transition-colors ${pkg.name === "@oidfed/explorer" ? "bg-brand-50/50 dark:bg-brand-900/10" : ""}`}
												>
													<td className="px-4 py-2 font-mono text-xs text-brand-600 dark:text-brand-400">
														{pkg.name}
														{pkg.name === "@oidfed/explorer" && (
															<Badge variant="secondary" className="ml-2 text-[10px] px-1.5 py-0">
																current
															</Badge>
														)}
													</td>
													<td className="px-4 py-2 text-muted-foreground">{pkg.role}</td>
													{"url" in pkg && (
														<td className="px-4 py-2">
															<a
																href={pkg.url}
																target="_blank"
																rel="noopener noreferrer"
																className="inline-flex items-center gap-1 text-xs text-brand-600 underline underline-offset-2 hover:text-brand-800 dark:text-brand-400 dark:hover:text-brand-300"
															>
																<ExternalLink className="size-3" />
																{new URL(pkg.url).hostname}
															</a>
														</td>
													)}
												</tr>
											))}
										</tbody>
									</table>
								</div>
							</div>
						);
					})}
				</div>
			</section>

			{/* Features grid */}
			<section className="space-y-4">
				<h2 className="text-2xl font-semibold tracking-tight">Features</h2>
				<div className="grid grid-cols-1 gap-4 md:grid-cols-2">
					{features.map((feature) => (
						<Card
							key={feature.path}
							className="cursor-pointer transition-colors hover:bg-accent/50"
							onClick={() => navigate(feature.path)}
						>
							<CardHeader className="pb-2">
								<CardTitle className="flex items-center gap-2 text-base">
									<feature.icon className="size-4 text-brand-500 dark:text-brand-400" />
									{feature.name}
								</CardTitle>
							</CardHeader>
							<CardContent>
								<p className="text-sm text-muted-foreground">{feature.description}</p>
							</CardContent>
						</Card>
					))}
				</div>
			</section>

			{/* Useful links */}
			<section className="space-y-4">
				<h2 className="text-2xl font-semibold tracking-tight">Links</h2>
				<div className="flex flex-wrap gap-4">
					<a
						href="https://oidfed.com"
						target="_blank"
						rel="noopener noreferrer"
						className="flex items-center gap-1 text-sm underline underline-offset-2 hover:text-foreground text-muted-foreground"
					>
						<ExternalLink className="size-3" />
						oidfed.com — Project home
					</a>
					<a
						href="https://github.com/Dahkenangnon/oidfed"
						target="_blank"
						rel="noopener noreferrer"
						className="flex items-center gap-1 text-sm underline underline-offset-2 hover:text-foreground text-muted-foreground"
					>
						<ExternalLink className="size-3" />
						GitHub: Dahkenangnon/oidfed — Monorepo
					</a>
				</div>
			</section>
		</div>
	);
}
