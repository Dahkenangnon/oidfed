import { Button } from "@oidfed/ui";
import {
	ArrowUpRight,
	BookOpen,
	ExternalLink,
	Github,
	ShieldCheck,
	Telescope,
} from "lucide-react";
import { Link } from "react-router";
import { ThemeToggle } from "~/components/theme-toggle";
import { getLessonsByPhase, lessons, phaseOrder, phases } from "~/data/lessons";
import { buildMeta, courseJsonLd, organizationJsonLd } from "~/lib/seo";
import type { Route } from "./+types/home";

export const handle = { lastUpdated: "2026-04-28" };

export function meta(_args: Route.MetaArgs) {
	return buildMeta({
		title: "Learn OpenID Federation 1.0 — Interactive Course | @oidfed",
		description:
			"Interactive OpenID Federation 1.0 course — 15 lessons from first principles to federation topology design. Trust Anchors, Entity Configurations, Trust Chains, Subordinate Statements, Metadata Policy, Trust Marks, Federation Endpoints, automatic + explicit client registration.",
		path: "/",
		jsonLd: [organizationJsonLd, courseJsonLd],
	});
}

export default function Home() {
	return (
		<div className="h-screen flex flex-col overflow-hidden">
			<HeroStyles />
			<AppHeader />
			<div className="flex-1 overflow-y-auto">
				<Hero />
				<Curriculum />
				<Footer />
			</div>
		</div>
	);
}

// ─────────────────────────────────────────────────────────────────────────────
// Header
// ─────────────────────────────────────────────────────────────────────────────

function AppHeader() {
	return (
		<header className="shrink-0 z-50 border-b border-border/60 bg-background/80 backdrop-blur">
			<div className="max-w-6xl mx-auto flex items-center justify-between h-14 px-6">
				<Link to="/" className="flex items-center gap-2">
					<div className="flex size-7 items-center justify-center rounded-md bg-brand-500 text-white">
						<BookOpen className="size-3.5" />
					</div>
					<span className="font-heading font-semibold text-[15px] tracking-tight">
						Learn OpenID Federation
					</span>
				</Link>
				<div className="flex items-center gap-1">
					<Button
						variant="ghost"
						size="sm"
						render={
							<a
								href="https://explore.oidfed.com"
								target="_blank"
								rel="noopener noreferrer"
								aria-label="OidFed Explorer"
							/>
						}
					>
						<Telescope className="size-3.5" />
						Explorer
						<ExternalLink className="size-3 opacity-60" />
					</Button>
					<Button
						variant="ghost"
						size="sm"
						render={
							<a
								href="https://oidfed.com"
								target="_blank"
								rel="noopener noreferrer"
								aria-label="OidFed project home"
							/>
						}
					>
						Project Home
						<ExternalLink className="size-3 opacity-60" />
					</Button>
					<Button
						variant="ghost"
						size="sm"
						render={
							<a
								href="https://github.com/Dahkenangnon/oidfed"
								target="_blank"
								rel="noopener noreferrer"
								aria-label="OidFed on GitHub"
							/>
						}
					>
						<Github className="size-3.5" />
					</Button>
					<ThemeToggle />
				</div>
			</div>
		</header>
	);
}

// ─────────────────────────────────────────────────────────────────────────────
// §00 · Hero
// ─────────────────────────────────────────────────────────────────────────────

function Hero() {
	return (
		<section className="relative border-b border-border/60 overflow-hidden">
			{/* Dot grid */}
			<div
				aria-hidden
				className="pointer-events-none absolute inset-0 opacity-[0.45] [mask-image:radial-gradient(ellipse_at_center,black_20%,transparent_75%)]"
				style={{
					backgroundImage:
						"radial-gradient(currentColor 1px, transparent 1px), radial-gradient(currentColor 1px, transparent 1px)",
					backgroundSize: "28px 28px, 28px 28px",
					backgroundPosition: "0 0, 14px 14px",
					color: "oklch(var(--muted-foreground) / 0.18)",
				}}
			/>
			{/* Accent glow */}
			<div
				aria-hidden
				className="pointer-events-none absolute left-1/2 top-0 -z-10 h-[380px] w-[900px] -translate-x-1/2 rounded-full bg-brand-500/10 blur-3xl dark:bg-brand-500/15"
			/>

			<div className="relative mx-auto grid max-w-6xl gap-12 px-6 py-16 sm:py-20 lg:grid-cols-[1.15fr_1fr] lg:items-center lg:gap-16 lg:py-28">
				{/* Left — text */}
				<div className="fade-rise">
					<div className="inline-flex items-center gap-2.5 rounded-full bg-primary px-3.5 py-1.5 font-mono text-[10.5px] uppercase tracking-[0.2em] text-primary-foreground shadow-sm ring-1 ring-primary/20">
						<span
							className="relative inline-flex size-1.5 items-center justify-center"
							aria-hidden
						>
							<span className="absolute inline-flex size-full animate-ping rounded-full bg-primary-foreground opacity-70" />
							<span className="relative inline-flex size-1.5 rounded-full bg-primary-foreground" />
						</span>
						<span className="tabular-nums">§00</span>
						<span className="h-3 w-px bg-primary-foreground/40" aria-hidden />
						<span>Interactive course · {lessons.length} lessons</span>
					</div>

					<h1 className="mt-6 font-heading text-[40px] font-bold leading-[1.02] tracking-[-0.03em] text-balance sm:text-[56px] lg:text-[68px] xl:text-[76px]">
						<span className="block">Learn OpenID</span>
						<span className="block bg-gradient-to-r from-brand-600 via-brand-500 to-brand-300 bg-clip-text text-transparent dark:from-brand-300 dark:via-brand-400 dark:to-brand-500">
							Federation 1.0.
						</span>
					</h1>

					<p className="mt-6 max-w-xl text-lg leading-relaxed text-muted-foreground text-balance">
						A structured, interactive guide — from first principles to production deployment.{" "}
						{lessons.length} lessons, hands-on exercises, and real-world use cases.
					</p>

					<p className="mt-4 max-w-xl text-[15px] leading-relaxed text-muted-foreground/80">
						Trust Anchors, Entity Configurations, Trust Chains, Subordinate Statements, Metadata
						Policy, Trust Marks, Federation Endpoints, automatic + explicit client registration —
						taught from first principles and grounded in the{" "}
						<a
							href="https://openid.net/specs/openid-federation-1_0.html"
							target="_blank"
							rel="noopener noreferrer"
							className="underline underline-offset-2 decoration-muted-foreground/40 hover:decoration-foreground hover:text-foreground"
						>
							OpenID Federation 1.0 specification
						</a>
						.
					</p>

					<div className="mt-10 flex flex-wrap items-center gap-3">
						<Button size="lg" render={<Link to="/lessons/what-is-federation" />} className="group">
							Start Lesson 01
							<ArrowUpRight className="ml-1.5 size-4 transition-transform group-hover:-translate-y-0.5 group-hover:translate-x-0.5" />
						</Button>
						<Button variant="outline" size="lg" render={<a href="#curriculum" />}>
							View Curriculum
						</Button>
					</div>

					<div className="mt-10 flex flex-wrap items-center gap-x-6 gap-y-2 font-mono text-[11px] uppercase tracking-[0.16em] text-muted-foreground">
						<span className="flex items-center gap-1.5">
							<span className="inline-block size-1.5 rounded-full bg-emerald-500" />
							{lessons.length} lessons
						</span>
						<span className="flex items-center gap-1.5">
							<span className="inline-block size-1.5 rounded-full bg-brand-500" />
							Spec-accurate
						</span>
						<span className="flex items-center gap-1.5">
							<span className="inline-block size-1.5 rounded-full bg-emerald-500" />
							Free · Apache 2.0 · MIT
						</span>
					</div>
				</div>

				{/* Right — trust mark credential */}
				<div className="relative fade-rise delay-2 hidden lg:block">
					<div className="relative rounded-2xl border border-border/60 bg-card/40 p-5 shadow-sm backdrop-blur-sm sm:p-7">
						{/* Credential header */}
						<div className="mb-5 flex items-center justify-between border-b border-border/60 pb-3">
							<div className="flex items-center gap-2 font-mono text-[10.5px] uppercase tracking-[0.2em] text-muted-foreground">
								<ShieldCheck className="size-3.5 text-brand-500" />
								Trust Mark · Certified
							</div>
							<span className="rounded-sm border border-emerald-500/40 bg-emerald-500/10 px-1.5 py-0.5 font-mono text-[9.5px] font-semibold uppercase tracking-[0.2em] text-emerald-700 dark:text-emerald-400">
								Valid
							</span>
						</div>

						{/* The seal */}
						<TrustMarkSeal />

						{/* Credential metadata */}
						<dl className="mt-5 grid grid-cols-3 gap-3 border-t border-border/60 pt-4 font-mono text-[10px] uppercase tracking-[0.14em]">
							<div>
								<dt className="text-muted-foreground/70">Issuer</dt>
								<dd className="mt-1 text-foreground">Trust Anchor</dd>
							</div>
							<div>
								<dt className="text-muted-foreground/70">Serial</dt>
								<dd className="mt-1 tabular-nums text-foreground">4f2a…c3e1</dd>
							</div>
							<div>
								<dt className="text-muted-foreground/70">Validity</dt>
								<dd className="mt-1 tabular-nums text-foreground">2026–2027</dd>
							</div>
						</dl>
					</div>
					<p className="mt-3 pl-2 font-mono text-[10.5px] uppercase tracking-[0.22em] text-muted-foreground/80">
						A Trust Mark — a signed, verifiable seal that an entity meets federation requirements.
					</p>
				</div>
			</div>
		</section>
	);
}

function TrustMarkSeal() {
	// 60 radial tick marks between r=170 and r=182 for a guilloché-style engraving
	const ticks = Array.from({ length: 60 }, (_, i) => {
		const angle = (i * Math.PI * 2) / 60 - Math.PI / 2;
		const x1 = 250 + Math.cos(angle) * 170;
		const y1 = 250 + Math.sin(angle) * 170;
		const x2 = 250 + Math.cos(angle) * 182;
		const y2 = 250 + Math.sin(angle) * 182;
		return { x1, y1, x2, y2, key: i };
	});

	return (
		<svg
			viewBox="0 0 500 500"
			fill="none"
			aria-hidden
			className="mx-auto block w-full max-w-[420px]"
		>
			<defs>
				{/* Top arc — text flows left→right over top, path at r=195 */}
				<path id="tm-arc-top" d="M 55 250 A 195 195 0 0 1 445 250" />
				{/* Bottom arc — text flows left→right under bottom */}
				<path id="tm-arc-bot" d="M 60 250 A 190 190 0 0 0 440 250" />

				{/* Shield gradient */}
				<linearGradient id="tm-shield" x1="0" y1="0" x2="0" y2="1">
					<stop offset="0%" className="[stop-color:var(--color-brand-400)]" />
					<stop offset="100%" className="[stop-color:var(--color-brand-600)]" />
				</linearGradient>

				{/* Soft radial glow behind seal */}
				<radialGradient id="tm-glow">
					<stop offset="0%" className="[stop-color:var(--color-brand-500)]" stopOpacity="0.18" />
					<stop offset="70%" className="[stop-color:var(--color-brand-500)]" stopOpacity="0" />
				</radialGradient>
			</defs>

			{/* Backdrop glow */}
			<circle cx="250" cy="250" r="230" fill="url(#tm-glow)" />

			{/* Outer double ring */}
			<circle
				cx="250"
				cy="250"
				r="220"
				className="stroke-brand-500/30 dark:stroke-brand-400/25"
				strokeWidth="1"
			/>
			<circle
				cx="250"
				cy="250"
				r="212"
				className="stroke-brand-500/20 dark:stroke-brand-400/15"
				strokeWidth="1"
			/>

			{/* Guilloché tick marks */}
			{ticks.map((t) => (
				<line
					key={t.key}
					x1={t.x1}
					y1={t.y1}
					x2={t.x2}
					y2={t.y2}
					className="stroke-brand-500/35 dark:stroke-brand-400/25"
					strokeWidth="0.8"
				/>
			))}

			{/* Inner boundary (the seal interior edge) */}
			<circle
				cx="250"
				cy="250"
				r="165"
				className="stroke-brand-500/50 dark:stroke-brand-400/40"
				strokeWidth="2"
			/>
			<circle cx="250" cy="250" r="160" className="fill-background/80" />

			{/* Cardinal decorative dots */}
			<circle cx="250" cy="32" r="2.5" className="fill-brand-500 dark:fill-brand-400" />
			<circle cx="468" cy="250" r="2.5" className="fill-brand-500 dark:fill-brand-400" />
			<circle cx="250" cy="468" r="2.5" className="fill-brand-500 dark:fill-brand-400" />
			<circle cx="32" cy="250" r="2.5" className="fill-brand-500 dark:fill-brand-400" />

			{/* Top arc text */}
			<text
				className="fill-muted-foreground font-mono"
				fontSize="13"
				letterSpacing="3.5"
				style={{ textTransform: "uppercase" }}
			>
				<textPath href="#tm-arc-top" startOffset="50%" textAnchor="middle">
					· OpenID Federation 1.0 · Trust Mark ·
				</textPath>
			</text>

			{/* Bottom arc text */}
			<text
				className="fill-muted-foreground font-mono"
				fontSize="11"
				letterSpacing="3"
				style={{ textTransform: "uppercase" }}
			>
				<textPath href="#tm-arc-bot" startOffset="50%" textAnchor="middle">
					Verified · Issued by Trust Anchor
				</textPath>
			</text>

			{/* Central shield — coat-of-arms style */}
			<path
				d="M 250 140 L 315 168 L 315 255 Q 315 320, 250 350 Q 185 320, 185 255 L 185 168 Z"
				fill="url(#tm-shield)"
				className="stroke-brand-600 dark:stroke-brand-300"
				strokeWidth="2.5"
				strokeLinejoin="round"
			/>

			{/* Inner shield bevel */}
			<path
				d="M 250 155 L 304 178 L 304 252 Q 304 310, 250 336 Q 196 310, 196 252 L 196 178 Z"
				fill="none"
				className="stroke-white/25"
				strokeWidth="1"
				strokeLinejoin="round"
			/>

			{/* Large checkmark */}
			<path
				d="M 212 248 L 240 277 L 292 212"
				fill="none"
				stroke="white"
				strokeWidth="9"
				strokeLinecap="round"
				strokeLinejoin="round"
			/>

			{/* Label under shield */}
			<text
				x="250"
				y="385"
				textAnchor="middle"
				className="fill-brand-600 dark:fill-brand-400 font-mono font-semibold"
				fontSize="11"
				letterSpacing="4"
			>
				VERIFIED
			</text>
			<line
				x1="215"
				y1="395"
				x2="285"
				y2="395"
				className="stroke-brand-500/40 dark:stroke-brand-400/30"
				strokeWidth="0.8"
			/>
		</svg>
	);
}

// ─────────────────────────────────────────────────────────────────────────────
// §01+ · Curriculum
// ─────────────────────────────────────────────────────────────────────────────

function Curriculum() {
	return (
		<section id="curriculum" className="scroll-mt-16 border-b border-border/60 bg-muted/30">
			<div className="mx-auto max-w-6xl px-6 py-20 lg:py-24">
				<div className="max-w-2xl">
					<SignalLabel id="01" label="Curriculum" />
					<h2 className="mt-6 font-heading text-3xl font-semibold tracking-[-0.02em] text-balance sm:text-4xl">
						Five phases, {lessons.length} lessons.
					</h2>
					<p className="mt-4 max-w-xl text-[15px] leading-relaxed text-muted-foreground">
						Foundation concepts first, then core mechanics, advanced flows, a capstone scenario, and
						a deeper track for topology design and real-world adoption.
					</p>
				</div>

				<div className="mt-12 space-y-10">
					{phaseOrder.map((phaseId, phaseIdx) => {
						const phase = phases[phaseId];
						const phaseLessons = getLessonsByPhase(phaseId);
						const phaseNum = String(phaseIdx + 1).padStart(2, "0");
						return (
							<div key={phaseId}>
								<div className="flex items-center gap-3 font-mono text-[11px] uppercase tracking-[0.18em] text-muted-foreground">
									<span className={`tabular-nums ${phase.color}`}>§{phaseNum}</span>
									<span className={phase.color}>{phase.label}</span>
									<span className="h-px flex-1 bg-border" />
									<span className="tabular-nums">
										{phaseLessons.length} lesson{phaseLessons.length > 1 ? "s" : ""}
									</span>
								</div>

								<ul className="mt-5 divide-y divide-border/60 rounded-xl border border-border/60 bg-card/40">
									{phaseLessons.map((lesson) => (
										<li key={lesson.slug}>
											<Link
												to={`/lessons/${lesson.slug}`}
												className="group grid grid-cols-[auto_1fr_auto] items-center gap-4 p-4 transition-colors hover:bg-muted/50"
											>
												<span className="inline-flex size-8 items-center justify-center rounded-md border border-border/80 bg-muted font-mono text-[11px] font-semibold tabular-nums text-muted-foreground">
													{String(lesson.number).padStart(2, "0")}
												</span>
												<div className="min-w-0">
													<div className="font-heading text-[15.5px] font-semibold leading-snug tracking-tight">
														{lesson.title}
													</div>
													<div className="mt-0.5 text-[13.5px] leading-relaxed text-muted-foreground">
														{lesson.subtitle}
													</div>
												</div>
												<ArrowUpRight className="size-4 text-muted-foreground transition-colors group-hover:text-brand-500" />
											</Link>
										</li>
									))}
								</ul>
							</div>
						);
					})}
				</div>
			</div>
		</section>
	);
}

function SignalLabel({ id, label }: { id: string; label: string }) {
	return (
		<div className="flex items-center gap-3 font-mono text-[11px] uppercase tracking-[0.18em] text-muted-foreground">
			<span className="inline-flex size-1.5 rounded-full bg-brand-500" aria-hidden />
			<span className="tabular-nums">§{id}</span>
			<span className="h-px w-8 bg-border" aria-hidden />
			<span>{label}</span>
		</div>
	);
}

// ─────────────────────────────────────────────────────────────────────────────
// Footer
// ─────────────────────────────────────────────────────────────────────────────

function Footer() {
	return (
		<footer className="border-t border-border/60">
			<div className="mx-auto flex max-w-6xl flex-col items-center justify-between gap-3 px-6 py-6 font-mono text-[11px] uppercase tracking-[0.16em] text-muted-foreground sm:flex-row">
				<span className="flex items-center gap-1.5">
					<span className="inline-block size-1.5 rounded-full bg-emerald-500" aria-hidden />
					Last reviewed: {handle.lastUpdated}
				</span>
				<span className="tracking-[0.12em]">
					<span className="text-muted-foreground/70">By </span>
					<a
						href="https://github.com/Dahkenangnon"
						target="_blank"
						rel="noopener noreferrer"
						className="transition-colors hover:text-foreground"
					>
						Justin Dah-kenangnon
					</a>
				</span>
			</div>
		</footer>
	);
}

// ─────────────────────────────────────────────────────────────────────────────
// Animation styles
// ─────────────────────────────────────────────────────────────────────────────

function HeroStyles() {
	return (
		<style>{`
			@keyframes fade-rise {
				from { opacity: 0; transform: translateY(12px); }
				to { opacity: 1; transform: translateY(0); }
			}
			.fade-rise { animation: fade-rise 0.8s cubic-bezier(0.22, 1, 0.36, 1) both; }
			.delay-2 { animation-delay: 0.2s; }

			@media (prefers-reduced-motion: reduce) {
				.fade-rise { animation: none !important; }
			}
		`}</style>
	);
}
