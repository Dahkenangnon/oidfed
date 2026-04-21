import { Badge, Button, Card, CardHeader, CardPanel, CardTitle } from "@oidfed/ui";
import { ArrowRight, BookOpen, ExternalLink } from "lucide-react";
import { Link } from "react-router";
import { ThemeToggle } from "~/components/theme-toggle";
import { getLessonsByPhase, phaseOrder, phases } from "~/data/lessons";
import type { Route } from "./+types/home";

export const handle = { lastUpdated: "2026-04-20" };

export function meta(_args: Route.MetaArgs) {
	return [
		{ title: "Learn OpenID Federation — Interactive Course" },
		{
			name: "description",
			content:
				"An interactive course on OpenID Federation 1.0 — 15 lessons from first principles to federation topology design, with hands-on exercises and spec-accurate references.",
		},
		{ name: "author", content: "Justin Dah-kenangnon" },
		{ property: "og:title", content: "Learn OpenID Federation" },
		{
			property: "og:description",
			content:
				"An interactive course on OpenID Federation 1.0 — 15 lessons with hands-on exercises and spec-accurate references.",
		},
		{ property: "og:type", content: "website" },
		{
			property: "article:author",
			content: "https://dahkenangnon.com",
		},
	];
}

const phaseColors: Record<string, string> = {
	foundation: "bg-brand-500/10 text-brand-700 dark:text-brand-300",
	core: "bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
	advanced: "bg-purple-500/10 text-purple-700 dark:text-purple-300",
	capstone: "bg-orange-500/10 text-orange-700 dark:text-orange-300",
	deeper: "bg-teal-500/10 text-teal-700 dark:text-teal-300",
};

export default function Home() {
	return (
		<div className="h-screen flex flex-col overflow-hidden">
			{/* Header */}
			<header className="shrink-0 z-50 border-b border-border bg-background/80 backdrop-blur">
				<div className="max-w-6xl mx-auto flex items-center justify-between h-14 px-4">
					<Link to="/" className="flex items-center gap-2 font-semibold text-sm">
						<BookOpen className="size-4 text-primary" />
						Learn OpenID Federation
					</Link>
					<div className="flex items-center gap-2">
						<Button variant="ghost" size="sm" render={<Link to="/resources" />}>
							Resources
						</Button>
						<Button
							variant="ghost"
							size="sm"
							render={
								// biome-ignore lint/a11y/useAnchorContent: content rendered by Button children
								<a
									href="https://explore.oidfed.com"
									target="_blank"
									rel="noopener noreferrer"
									aria-label="OidFed Explorer"
								/>
							}
						>
							Explorer
							<ExternalLink className="ml-1 size-3" />
						</Button>
						<Button
							variant="ghost"
							size="sm"
							render={
								// biome-ignore lint/a11y/useAnchorContent: content rendered by Button children
								<a
									href="https://oidfed.com"
									target="_blank"
									rel="noopener noreferrer"
									aria-label="OidFed Home"
								/>
							}
						>
							Home
							<ExternalLink className="ml-1 size-3" />
						</Button>
						<ThemeToggle />
					</div>
				</div>
			</header>

			<div className="flex-1 overflow-y-auto">
				{/* Hero */}
				<section className="relative flex flex-col items-center justify-center py-24 text-center overflow-hidden">
					{/* Federation galaxy illustration */}
					<svg
						className="absolute inset-0 w-full h-full"
						viewBox="0 0 800 500"
						preserveAspectRatio="xMidYMid slice"
						fill="none"
						aria-hidden="true"
					>
						{/* Orbital paths */}
						<circle
							cx="400"
							cy="250"
							r="80"
							className="stroke-brand-500/15 dark:stroke-brand-400/10"
							strokeWidth="1"
						/>
						<circle
							cx="400"
							cy="250"
							r="160"
							className="stroke-brand-500/10 dark:stroke-brand-400/8"
							strokeWidth="1"
						/>
						<circle
							cx="400"
							cy="250"
							r="240"
							className="stroke-teal-500/8 dark:stroke-teal-400/5"
							strokeWidth="1"
						/>

						{/* Trust Anchor (center) */}
						<circle cx="400" cy="250" r="14" className="fill-brand-500/25 dark:fill-brand-400/15" />
						<circle
							cx="400"
							cy="250"
							r="22"
							className="stroke-brand-500/20 dark:stroke-brand-400/12"
							strokeWidth="1.5"
						/>

						{/* Intermediate Authorities (mid ring) */}
						<circle cx="480" cy="250" r="8" className="fill-teal-500/20 dark:fill-teal-400/12" />
						<circle cx="360" cy="180" r="8" className="fill-teal-500/20 dark:fill-teal-400/12" />
						<circle cx="320" cy="300" r="8" className="fill-teal-500/20 dark:fill-teal-400/12" />
						<circle cx="440" cy="330" r="8" className="fill-teal-500/20 dark:fill-teal-400/12" />

						{/* Connections: TA → Intermediates */}
						<line
							x1="400"
							y1="250"
							x2="480"
							y2="250"
							className="stroke-brand-500/15 dark:stroke-brand-400/10"
							strokeWidth="1.5"
						/>
						<line
							x1="400"
							y1="250"
							x2="360"
							y2="180"
							className="stroke-brand-500/15 dark:stroke-brand-400/10"
							strokeWidth="1.5"
						/>
						<line
							x1="400"
							y1="250"
							x2="320"
							y2="300"
							className="stroke-brand-500/15 dark:stroke-brand-400/10"
							strokeWidth="1.5"
						/>
						<line
							x1="400"
							y1="250"
							x2="440"
							y2="330"
							className="stroke-brand-500/15 dark:stroke-brand-400/10"
							strokeWidth="1.5"
						/>

						{/* Leaf Entities (outer ring) */}
						<circle cx="560" cy="210" r="5" className="fill-brand-500/12 dark:fill-brand-400/8" />
						<circle cx="550" cy="290" r="5" className="fill-brand-500/12 dark:fill-brand-400/8" />
						<circle cx="280" cy="130" r="5" className="fill-brand-500/12 dark:fill-brand-400/8" />
						<circle cx="310" cy="170" r="5" className="fill-brand-500/12 dark:fill-brand-400/8" />
						<circle cx="220" cy="320" r="5" className="fill-teal-500/12 dark:fill-teal-400/8" />
						<circle cx="270" cy="370" r="5" className="fill-teal-500/12 dark:fill-teal-400/8" />
						<circle cx="500" cy="390" r="5" className="fill-teal-500/12 dark:fill-teal-400/8" />
						<circle cx="410" cy="410" r="5" className="fill-teal-500/12 dark:fill-teal-400/8" />
						<circle cx="600" cy="250" r="5" className="fill-brand-500/12 dark:fill-brand-400/8" />
						<circle cx="200" cy="250" r="5" className="fill-teal-500/12 dark:fill-teal-400/8" />

						{/* Connections: Intermediates → Leaves */}
						<line
							x1="480"
							y1="250"
							x2="560"
							y2="210"
							className="stroke-teal-500/10 dark:stroke-teal-400/6"
							strokeWidth="1"
						/>
						<line
							x1="480"
							y1="250"
							x2="550"
							y2="290"
							className="stroke-teal-500/10 dark:stroke-teal-400/6"
							strokeWidth="1"
						/>
						<line
							x1="480"
							y1="250"
							x2="600"
							y2="250"
							className="stroke-teal-500/10 dark:stroke-teal-400/6"
							strokeWidth="1"
						/>
						<line
							x1="360"
							y1="180"
							x2="280"
							y2="130"
							className="stroke-teal-500/10 dark:stroke-teal-400/6"
							strokeWidth="1"
						/>
						<line
							x1="360"
							y1="180"
							x2="310"
							y2="170"
							className="stroke-teal-500/10 dark:stroke-teal-400/6"
							strokeWidth="1"
						/>
						<line
							x1="320"
							y1="300"
							x2="220"
							y2="320"
							className="stroke-teal-500/10 dark:stroke-teal-400/6"
							strokeWidth="1"
						/>
						<line
							x1="320"
							y1="300"
							x2="270"
							y2="370"
							className="stroke-teal-500/10 dark:stroke-teal-400/6"
							strokeWidth="1"
						/>
						<line
							x1="320"
							y1="300"
							x2="200"
							y2="250"
							className="stroke-teal-500/10 dark:stroke-teal-400/6"
							strokeWidth="1"
						/>
						<line
							x1="440"
							y1="330"
							x2="500"
							y2="390"
							className="stroke-teal-500/10 dark:stroke-teal-400/6"
							strokeWidth="1"
						/>
						<line
							x1="440"
							y1="330"
							x2="410"
							y2="410"
							className="stroke-teal-500/10 dark:stroke-teal-400/6"
							strokeWidth="1"
						/>
					</svg>

					{/* Gradient fade: bottom → top so illustration dissolves into Curriculum */}
					<div className="absolute inset-x-0 bottom-0 h-1/3 bg-gradient-to-t from-background to-transparent" />

					<div className="relative z-10">
						<Badge variant="outline" className="mb-6">
							OpenID Federation 1.0
						</Badge>
						<h1 className="text-4xl font-bold tracking-tight sm:text-5xl lg:text-6xl max-w-3xl">
							Learn{" "}
							<span className="bg-gradient-to-r from-brand-500 to-teal-500 bg-clip-text text-transparent">
								OpenID Federation
							</span>
						</h1>
						<p className="mt-4 max-w-xl text-lg text-muted-foreground mx-auto">
							A structured, interactive guide — from core concepts to production deployment. 15
							lessons, hands-on exercises, and real-world use cases.
						</p>
						<div className="mt-8 flex gap-3 justify-center">
							<Button size="lg" render={<Link to="/lessons/what-is-federation" />}>
								Start Now
								<ArrowRight className="ml-2 size-4" />
							</Button>
							<Button variant="outline" size="lg" render={<Link to="/resources" />}>
								Resources
								<ExternalLink className="ml-2 size-4" />
							</Button>
						</div>
					</div>
				</section>

				{/* Phase Grid */}
				<section className="max-w-6xl mx-auto px-4 pb-24 w-full">
					<h2 className="text-2xl font-bold text-center mb-8">Curriculum</h2>
					<div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
						{phaseOrder.map((phaseId) => {
							const phase = phases[phaseId];
							const phaseLessons = getLessonsByPhase(phaseId);
							return (
								<Card key={phaseId}>
									<CardHeader>
										<Badge variant="secondary" className={phaseColors[phaseId]}>
											{phase.label}
										</Badge>
										<CardTitle className="text-base mt-2">
											{phaseLessons.length} lesson
											{phaseLessons.length > 1 ? "s" : ""}
										</CardTitle>
									</CardHeader>
									<CardPanel className="pt-0">
										<ul className="space-y-1.5">
											{phaseLessons.map((lesson) => (
												<li key={lesson.slug}>
													<Link
														to={`/lessons/${lesson.slug}`}
														className="text-sm text-muted-foreground hover:text-foreground transition-colors flex items-center gap-2"
													>
														<span>{lesson.emoji}</span>
														<span>{lesson.title}</span>
													</Link>
												</li>
											))}
										</ul>
									</CardPanel>
								</Card>
							);
						})}
					</div>
				</section>

				{/* Footer */}
				<footer className="border-t border-border py-6 text-center text-sm text-muted-foreground">
					<p>
						Last reviewed: {handle.lastUpdated} · By{" "}
						<a
							href="https://dahkenangnon.com"
							className="text-primary hover:underline"
							target="_blank"
							rel="noopener noreferrer"
						>
							Justin Dah-kenangnon
						</a>
					</p>
				</footer>
			</div>
		</div>
	);
}
