import { Badge, buttonVariants, Card, CardHeader, CardTitle } from "@oidfed/ui";
import { ExternalLink, Github, Globe, Package, Terminal } from "lucide-react";
import { HeroBackground } from "../components/illustrations";

export const handle = { lastUpdated: "2026-04-20" };

export function meta() {
	return [
		{ title: "About — @oidfed" },
		{
			name: "description",
			content:
				"About the @oidfed project — the complete OpenID Federation 1.0 implementation for JavaScript.",
		},
		{ property: "og:title", content: "About — @oidfed" },
		{
			property: "og:description",
			content:
				"About the @oidfed project — the complete OpenID Federation 1.0 implementation for JavaScript.",
		},
		{ property: "og:type", content: "website" },
	];
}

const highlights = [
	{ label: "Packages", value: "4" },
	{ label: "Apps", value: "3" },
	{ label: "CLI Commands", value: "14" },
	{ label: "License", value: "MIT" },
];

const architecture = [
	{
		icon: Package,
		title: "Spec Packages",
		items: ["@oidfed/core", "@oidfed/authority", "@oidfed/leaf", "@oidfed/oidc"],
		description:
			"Full OpenID Federation 1.0 coverage — from primitives to OIDC registration flows.",
	},
	{
		icon: Globe,
		title: "Apps",
		items: ["@oidfed/home", "@oidfed/learn", "@oidfed/explorer"],
		description:
			"Homepage, interactive course (15 lessons), and visual federation topology explorer.",
	},
	{
		icon: Terminal,
		title: "Tools",
		items: ["@oidfed/cli"],
		description:
			"Inspect, validate, and debug federation deployments from the command line — 14 commands.",
	},
];

export default function About() {
	return (
		<article>
			{/* Hero */}
			<section className="relative overflow-hidden border-b border-border py-16 sm:py-20">
				<HeroBackground />
				<div className="relative mx-auto max-w-3xl px-6 text-center">
					<Badge variant="secondary" className="mb-4">
						About the project
					</Badge>
					<h1 className="font-heading text-3xl font-bold tracking-tight sm:text-4xl">
						The complete{" "}
						<span className="bg-gradient-to-r from-brand-600 to-brand-400 bg-clip-text text-transparent dark:from-brand-300 dark:to-brand-500">
							OpenID Federation 1.0
						</span>{" "}
						implementation for JavaScript
					</h1>
					<p className="mx-auto mt-4 max-w-xl text-muted-foreground">
						Runtime-agnostic, spec-compliant, built on Web API standards. Modular by design — use
						only what you need.
					</p>
				</div>
			</section>

			{/* Stats */}
			<section className="border-b border-border bg-muted/30 py-8">
				<div className="mx-auto grid max-w-3xl grid-cols-2 gap-6 px-6 sm:grid-cols-4">
					{highlights.map((stat) => (
						<div key={stat.label} className="text-center">
							<p className="font-heading text-2xl font-bold text-primary">{stat.value}</p>
							<p className="mt-1 text-xs text-muted-foreground">{stat.label}</p>
						</div>
					))}
				</div>
			</section>

			{/* Architecture */}
			<section className="py-16">
				<div className="mx-auto max-w-3xl px-6">
					<h2 className="font-heading text-2xl font-bold tracking-tight">Architecture</h2>
					<p className="mt-2 text-muted-foreground">
						A monorepo structured into packages, apps, and tools — each independently versioned.
					</p>
					<div className="mt-8 grid gap-4">
						{architecture.map((section) => (
							<Card
								key={section.title}
								className="group transition-all hover:-translate-y-0.5 hover:shadow-md"
							>
								<CardHeader>
									<section.icon className="size-5 text-primary" />
									<CardTitle className="text-base">{section.title}</CardTitle>
								</CardHeader>
								<div className="px-6 pb-6">
									<p className="text-sm text-muted-foreground">{section.description}</p>
									<div className="mt-3 flex flex-wrap gap-2">
										{section.items.map((item) => (
											<Badge key={item} variant="secondary" className="font-mono text-xs">
												{item}
											</Badge>
										))}
									</div>
								</div>
							</Card>
						))}
					</div>
				</div>
			</section>

			{/* Author & Contributing */}
			<section className="border-t border-border py-16">
				<div className="mx-auto max-w-3xl px-6">
					<div className="grid gap-12 sm:grid-cols-2">
						<div>
							<h2 className="font-heading text-xl font-bold tracking-tight">Author</h2>
							<p className="mt-3 text-sm text-muted-foreground">
								Built by{" "}
								<a
									href="https://dahkenangnon.com"
									target="_blank"
									rel="noopener noreferrer"
									className="text-foreground underline underline-offset-4 hover:no-underline"
								>
									Justin Dah-kenangnon
								</a>
								.
							</p>
						</div>
						<div>
							<h2 className="font-heading text-xl font-bold tracking-tight">Contributing</h2>
							<p className="mt-3 text-sm text-muted-foreground">
								Contributions are welcome. See the{" "}
								<a
									href="https://github.com/Dahkenangnon/oidfed/blob/main/CONTRIBUTING.md"
									target="_blank"
									rel="noopener noreferrer"
									className="text-foreground underline underline-offset-4 hover:no-underline"
								>
									contributing guidelines
								</a>{" "}
								for details.
							</p>
						</div>
					</div>

					<div className="mt-12 rounded-lg border border-border bg-card p-6">
						<p className="text-sm text-muted-foreground">
							Released under the{" "}
							<a
								href="https://github.com/Dahkenangnon/oidfed/blob/main/LICENSE"
								target="_blank"
								rel="noopener noreferrer"
								className="text-foreground underline underline-offset-4 hover:no-underline"
							>
								MIT License
							</a>
							. Free for commercial and open-source use.
						</p>
					</div>
				</div>
			</section>

			{/* CTA Links */}
			<section className="border-t border-border bg-muted/30 py-12">
				<div className="mx-auto flex max-w-3xl flex-wrap justify-center gap-3 px-6">
					<a
						href="https://github.com/Dahkenangnon/oidfed"
						target="_blank"
						rel="noopener noreferrer"
						className={buttonVariants({ variant: "default", size: "sm" })}
					>
						<Github className="mr-1.5 size-4" />
						GitHub
					</a>
					<a
						href="https://www.npmjs.com/org/oidfed"
						target="_blank"
						rel="noopener noreferrer"
						className={buttonVariants({ variant: "outline", size: "sm" })}
					>
						npm <ExternalLink className="ml-1 size-3" />
					</a>
					<a
						href="https://learn.oidfed.com"
						target="_blank"
						rel="noopener noreferrer"
						className={buttonVariants({ variant: "outline", size: "sm" })}
					>
						Learn <ExternalLink className="ml-1 size-3" />
					</a>
					<a
						href="https://explore.oidfed.com"
						target="_blank"
						rel="noopener noreferrer"
						className={buttonVariants({ variant: "outline", size: "sm" })}
					>
						Explorer <ExternalLink className="ml-1 size-3" />
					</a>
				</div>
			</section>
		</article>
	);
}
