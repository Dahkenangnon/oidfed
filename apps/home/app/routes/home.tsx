import { Badge, buttonVariants, Card, CardTitle } from "@oidfed/ui";
import {
	ArrowRight,
	ArrowUpRight,
	CheckCircle2,
	ExternalLink,
	Globe,
	Network,
	Package,
	Shield,
	Terminal,
} from "lucide-react";
import { Link } from "react-router";
import { buildMeta, organizationJsonLd, softwareSourceCodeJsonLd, websiteJsonLd } from "../lib/seo";
import type { Route } from "./+types/home";

export const handle = { lastUpdated: "2026-04-25" };

export function meta(_args: Route.MetaArgs) {
	return buildMeta({
		title: "OpenID Federation 1.0 for JavaScript — @oidfed",
		description:
			"The complete OpenID Federation 1.0 implementation for JavaScript — runtime-agnostic, spec-compliant, built on Web API standards. Trust Anchors, Entity Configurations, Trust Chains, Metadata Policy, Trust Marks, and automatic / explicit client registration across Node.js, Deno, Bun, workerd, Electron, and browsers.",
		path: "/",
		jsonLd: [organizationJsonLd, websiteJsonLd, softwareSourceCodeJsonLd],
	});
}

// ─────────────────────────────────────────────────────────────────────────────
// Content data (unchanged)
// ─────────────────────────────────────────────────────────────────────────────

const specPackages = [
	{
		name: "@oidfed/core",
		install: "npm i @oidfed/core",
		description:
			"Federation primitives — entity statements, trust chain resolution, metadata policy, and cryptographic verification.",
		href: "https://www.npmjs.com/package/@oidfed/core",
	},
	{
		name: "@oidfed/authority",
		install: "npm i @oidfed/authority",
		description:
			"Trust Anchor and Intermediate Authority operations — subordinate management, statement issuance, and policy enforcement.",
		href: "https://www.npmjs.com/package/@oidfed/authority",
	},
	{
		name: "@oidfed/leaf",
		install: "npm i @oidfed/leaf",
		description:
			"Leaf Entity toolkit — Entity Configuration serving, authority discovery, and trust chain participation.",
		href: "https://www.npmjs.com/package/@oidfed/leaf",
	},
	{
		name: "@oidfed/oidc",
		install: "npm i @oidfed/oidc",
		description:
			"OpenID Connect and OAuth 2.0 federation flows — automatic and explicit client registration, Request Object validation.",
		href: "https://www.npmjs.com/package/@oidfed/oidc",
	},
];

const apps = [
	{
		name: "@oidfed/explorer",
		label: "Tool",
		description:
			"A visual tool for exploring live OpenID Federation deployments — inspect entity configurations, trace trust chains, and validate topology.",
		href: "https://explore.oidfed.com",
		preview: "explorer" as const,
	},
	{
		name: "@oidfed/learn",
		label: "Course",
		description:
			"An interactive course on OpenID Federation 1.0 — 15 lessons from first principles to federation topology design.",
		href: "https://learn.oidfed.com",
		preview: "learn" as const,
	},
	{
		name: "@oidfed/home",
		label: "Home",
		description: "Project homepage (this site).",
		href: "https://oidfed.com",
		preview: "home" as const,
	},
];

const adopters = [
	{
		name: "European Digital Identity Wallet (eIDAS 2.0)",
		detail:
			"The Architecture and Reference Framework references OpenID Federation for cross-border wallet trust establishment.",
		tag: "EU · ARF reference",
		region: "EU",
		href: "https://digital-strategy.ec.europa.eu/en/library/european-digital-identity-wallet-architecture-and-reference-framework",
	},
	{
		name: "Italy — SPID / CIE OIDC Federation",
		detail:
			"AgID published OpenID Connect Federation technical rules for SPID and CIE (Jan 2023); reference implementation italia/spid-cie-oidc-django.",
		tag: "AgID · technical rules",
		region: "IT",
		href: "https://www.agid.gov.it/en/agenzia/stampa-e-comunicazione/notizie/2023/01/17/openid-connect-technical-rules-spid-and-cie-are-online",
	},
	{
		name: "eduGAIN — OpenID Federation pilot",
		detail:
			"GÉANT eduGAIN is piloting OpenID Federation as the future trust technology alongside SAML (12-month pilot started July 2025).",
		tag: "Academic · GN5-2 pilot",
		region: "EU",
		href: "https://connect.geant.org/2025/10/13/edugain-piloting-use-of-openid-federation",
	},
	{
		name: "Identity Management for Agentic AI",
		detail:
			"OpenID Foundation whitepaper (Oct 2025) names OpenID Federation as a candidate interoperable trust fabric for AI agents operating across diverse domains.",
		tag: "AI agents · OID Foundation",
		region: "GLB",
		href: "https://openid.net/new-whitepaper-tackles-ai-agent-identity-challenges/",
	},
];

const whyReasons = [
	{
		title: "No more bilateral agreements",
		body: "Entities join a federation once. Trust is derived from a cryptographically signed chain — not from individual contracts between every pair of participants.",
		Icon: Network,
	},
	{
		title: "Verifiable trust at scale",
		body: "Every claim is signed. Trust Anchors publish constraints and metadata policies that are cryptographically enforced down the chain.",
		Icon: Shield,
	},
	{
		title: "Protocol-independent by design",
		body: "Works with OpenID Connect, OAuth 2.0, and beyond. The federation layer is orthogonal to the protocol used for authentication or authorization.",
		Icon: Globe,
	},
];

// ─────────────────────────────────────────────────────────────────────────────
// Micro-components
// ─────────────────────────────────────────────────────────────────────────────

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

/** Large hero federation graph with labeled nodes + pulsing TA. */
function HeroFederationGraph() {
	return (
		<svg
			viewBox="0 0 480 520"
			className="h-auto w-full"
			role="img"
			aria-label="OpenID Federation trust chain: a Trust Anchor at the root, two intermediate authorities, and four leaf entities."
		>
			<title>OpenID Federation trust chain diagram</title>
			<defs>
				<linearGradient id="edge-grad" x1="0%" y1="0%" x2="100%" y2="100%">
					<stop offset="0%" stopColor="#007acc" stopOpacity="0.9" />
					<stop offset="100%" stopColor="#4da6ff" stopOpacity="0.3" />
				</linearGradient>
				<radialGradient id="ta-glow" cx="50%" cy="50%" r="50%">
					<stop offset="0%" stopColor="#007acc" stopOpacity="0.45" />
					<stop offset="100%" stopColor="#007acc" stopOpacity="0" />
				</radialGradient>
				<filter id="edge-blur" x="-10%" y="-10%" width="120%" height="120%">
					<feGaussianBlur stdDeviation="0.8" />
				</filter>
			</defs>

			{/* grid ticks — static decorative backdrop, indexed keys are safe */}
			<g stroke="currentColor" strokeWidth="0.4" opacity="0.08" className="text-foreground">
				{Array.from({ length: 11 }, (_, i) => i * 52).map((y) => (
					<line key={`h-${y}`} x1="0" x2="480" y1={y} y2={y} />
				))}
				{Array.from({ length: 11 }, (_, i) => i * 48).map((x) => (
					<line key={`v-${x}`} y1="0" y2="520" x1={x} x2={x} />
				))}
			</g>

			{/* edges */}
			<g fill="none" stroke="url(#edge-grad)" strokeWidth="1.5" filter="url(#edge-blur)">
				<path d="M 240 100 C 240 160, 140 170, 130 230" className="chain-edge chain-edge-1" />
				<path d="M 240 100 C 240 160, 340 170, 350 230" className="chain-edge chain-edge-2" />
				<path d="M 130 260 C 130 320, 70 340, 70 400" className="chain-edge chain-edge-3" />
				<path d="M 130 260 C 130 320, 190 340, 190 400" className="chain-edge chain-edge-4" />
				<path d="M 350 260 C 350 320, 290 340, 290 400" className="chain-edge chain-edge-5" />
				<path d="M 350 260 C 350 320, 410 340, 410 400" className="chain-edge chain-edge-6" />
			</g>

			{/* Trust Anchor */}
			<g>
				<circle cx="240" cy="100" r="48" fill="url(#ta-glow)" className="animate-ta-pulse" />
				<circle cx="240" cy="100" r="20" fill="#007acc" />
				<circle
					cx="240"
					cy="100"
					r="20"
					fill="none"
					stroke="#80bfff"
					strokeWidth="1.5"
					opacity="0.5"
				/>
				<text
					x="240"
					y="57"
					textAnchor="middle"
					className="font-mono text-[9px] uppercase tracking-[0.2em] fill-muted-foreground"
				>
					Trust Anchor
				</text>
				<text
					x="240"
					y="72"
					textAnchor="middle"
					className="font-mono text-[9px] tracking-wide fill-muted-foreground/70"
				>
					ta.example.org
				</text>
			</g>

			{/* Intermediates */}
			<Node
				cx={130}
				cy={245}
				label="Intermediate"
				sub="ia-a.example.com"
				inner={12}
				ring={18}
				subY={286}
			/>
			<Node
				cx={350}
				cy={245}
				label="Intermediate"
				sub="ia-b.example.net"
				inner={12}
				ring={18}
				subY={286}
			/>

			{/* Leaves */}
			<Node cx={70} cy={415} label="OP" sub="op-1.example.com" inner={8} ring={13} />
			<Node cx={190} cy={415} label="RP" sub="rp-1.example.net" inner={8} ring={13} />
			<Node cx={290} cy={415} label="OP" sub="op-2.example.org" inner={8} ring={13} />
			<Node cx={410} cy={415} label="RP" sub="rp-2.example.com" inner={8} ring={13} />
		</svg>
	);
}

function Node({
	cx,
	cy,
	label,
	sub,
	inner,
	ring,
	subY,
}: {
	cx: number;
	cy: number;
	label: string;
	sub: string;
	inner: number;
	ring: number;
	subY?: number;
}) {
	return (
		<g>
			<circle
				cx={cx}
				cy={cy}
				r={ring}
				fill="none"
				stroke="#4da6ff"
				strokeWidth="1"
				opacity="0.45"
			/>
			<circle cx={cx} cy={cy} r={inner} fill="#007acc" />
			<text
				x={cx}
				y={cy + (ring + 14)}
				textAnchor="middle"
				className="font-mono text-[8px] uppercase tracking-[0.18em] fill-muted-foreground"
			>
				{label}
			</text>
			<text
				x={cx}
				y={subY ?? cy + ring + 26}
				textAnchor="middle"
				className="font-mono text-[8.5px] fill-muted-foreground/70"
			>
				{sub}
			</text>
		</g>
	);
}

/** Mini "resolved" status card that sits overlaying the graph bottom-right. */
function ResolvedStatus() {
	return (
		<div className="pointer-events-none absolute bottom-6 left-6 right-6 sm:left-auto sm:right-4 sm:max-w-[280px]">
			<div className="rounded-lg border border-border/60 bg-background/80 p-3 shadow-sm backdrop-blur-md">
				<div className="flex items-center gap-2">
					<CheckCircle2 className="size-3.5 text-emerald-500" />
					<span className="font-mono text-[11px] tracking-wide">chain.valid</span>
					<span className="ml-auto rounded-sm bg-emerald-500/10 px-1.5 py-0.5 font-mono text-[9px] font-medium uppercase tracking-wider text-emerald-600 dark:text-emerald-400">
						verified
					</span>
				</div>
				<div className="mt-2 font-mono text-[10px] leading-relaxed text-muted-foreground">
					<div className="flex justify-between">
						<span>statements</span>
						<span className="tabular-nums text-foreground">3</span>
					</div>
					<div className="flex justify-between">
						<span>policy_ops</span>
						<span className="tabular-nums text-foreground">4</span>
					</div>
					<div className="flex justify-between">
						<span>expires_in</span>
						<span className="tabular-nums text-foreground">23h 47m</span>
					</div>
				</div>
			</div>
		</div>
	);
}

/** Preview tile for each app card. */
function AppPreview({ kind }: { kind: "explorer" | "learn" | "home" }) {
	if (kind === "explorer") {
		return (
			<svg viewBox="0 0 280 140" className="h-full w-full" aria-hidden="true" role="presentation">
				<g stroke="currentColor" strokeWidth="0.5" opacity="0.15" className="text-foreground">
					{Array.from({ length: 7 }, (_, i) => (i + 1) * 20).map((y) => (
						<line key={`grid-${y}`} x1="0" x2="280" y1={y} y2={y} />
					))}
				</g>
				<g fill="none" stroke="#007acc" strokeWidth="1.2" opacity="0.6">
					<path d="M 40 110 L 70 70 L 110 90 L 150 40 L 200 60 L 240 30" />
				</g>
				<g fill="#007acc">
					<circle cx="40" cy="110" r="3" />
					<circle cx="70" cy="70" r="3" />
					<circle cx="110" cy="90" r="3" />
					<circle cx="150" cy="40" r="3" />
					<circle cx="200" cy="60" r="3" />
					<circle cx="240" cy="30" r="3" />
				</g>
				<text
					x="14"
					y="22"
					className="font-mono text-[8px] uppercase tracking-[0.2em] fill-muted-foreground"
				>
					chain / 6 statements
				</text>
			</svg>
		);
	}
	if (kind === "learn") {
		return (
			<svg viewBox="0 0 280 140" className="h-full w-full" aria-hidden="true" role="presentation">
				<g>
					{Array.from({ length: 15 }, (_, idx) => idx).map((i) => {
						const row = Math.floor(i / 5);
						const col = i % 5;
						const x = 40 + col * 52;
						const y = 40 + row * 32;
						return (
							<g key={`lesson-${x}-${y}`}>
								<circle cx={x} cy={y} r="10" className={i < 6 ? "fill-brand-500" : "fill-muted"} />
								<text
									x={x}
									y={y + 3}
									textAnchor="middle"
									className={`font-mono text-[8px] ${i < 6 ? "fill-white" : "fill-muted-foreground/60"}`}
								>
									{String(i + 1).padStart(2, "0")}
								</text>
							</g>
						);
					})}
				</g>
				<text
					x="14"
					y="22"
					className="font-mono text-[8px] uppercase tracking-[0.2em] fill-muted-foreground"
				>
					15 lessons
				</text>
			</svg>
		);
	}
	return (
		<svg viewBox="0 0 280 140" className="h-full w-full" aria-hidden="true" role="presentation">
			<g stroke="currentColor" strokeWidth="0.4" opacity="0.12" className="text-foreground">
				{Array.from({ length: 9 }, (_, i) => i * 35).map((x) => (
					<line key={`gx-${x}`} y1="0" y2="140" x1={x} x2={x} />
				))}
				{Array.from({ length: 5 }, (_, i) => i * 35).map((y) => (
					<line key={`gy-${y}`} x1="0" x2="280" y1={y} y2={y} />
				))}
			</g>
			<circle cx="140" cy="70" r="8" fill="#007acc" />
			<circle cx="140" cy="70" r="26" fill="none" stroke="#007acc" strokeWidth="1" opacity="0.3" />
			<circle cx="140" cy="70" r="44" fill="none" stroke="#007acc" strokeWidth="1" opacity="0.15" />
			<text
				x="14"
				y="22"
				className="font-mono text-[8px] uppercase tracking-[0.2em] fill-muted-foreground"
			>
				you are here
			</text>
		</svg>
	);
}

function CountryFlag({ region }: { region: string }) {
	return (
		<span className="inline-flex h-5 min-w-[28px] items-center justify-center rounded-sm border border-border/80 bg-muted px-1.5 font-mono text-[9px] font-semibold tracking-wider tabular-nums text-muted-foreground">
			{region}
		</span>
	);
}

// ─────────────────────────────────────────────────────────────────────────────
// Page
// ─────────────────────────────────────────────────────────────────────────────

export default function Home() {
	return (
		<div className="relative overflow-hidden">
			<PageAnimations />

			<Hero />
			<WhyFederation />
			<WhatsInside />
			<InProduction />
			<MachineIdentity />
		</div>
	);
}

/** Page-scoped CSS keyframes (CSS-only animations, no JS deps). */
function PageAnimations() {
	return (
		<style>{`
			@keyframes ta-pulse {
				0%, 100% { transform-origin: 240px 100px; transform: scale(1); opacity: 0.7; }
				50% { transform-origin: 240px 100px; transform: scale(1.12); opacity: 1; }
			}
			.animate-ta-pulse { animation: ta-pulse 3.6s ease-in-out infinite; }

			@keyframes chain-draw {
				from { stroke-dasharray: 240; stroke-dashoffset: 240; }
				to { stroke-dasharray: 240; stroke-dashoffset: 0; }
			}
			.chain-edge { animation: chain-draw 1.1s ease-out both; }
			.chain-edge-1 { animation-delay: 0.15s; }
			.chain-edge-2 { animation-delay: 0.2s; }
			.chain-edge-3 { animation-delay: 0.4s; }
			.chain-edge-4 { animation-delay: 0.45s; }
			.chain-edge-5 { animation-delay: 0.5s; }
			.chain-edge-6 { animation-delay: 0.55s; }

			@keyframes fade-rise {
				from { opacity: 0; transform: translateY(12px); }
				to { opacity: 1; transform: translateY(0); }
			}
			.fade-rise { animation: fade-rise 0.8s cubic-bezier(0.22, 1, 0.36, 1) both; }
			.delay-1 { animation-delay: 0.1s; }
			.delay-2 { animation-delay: 0.2s; }
			.delay-3 { animation-delay: 0.3s; }
			.delay-4 { animation-delay: 0.45s; }
			.delay-5 { animation-delay: 0.6s; }

			@media (prefers-reduced-motion: reduce) {
				.animate-ta-pulse, .chain-edge, .fade-rise { animation: none !important; }
			}
		`}</style>
	);
}

// ─────────────────────────────────────────────────────────────────────────────
// §01 · Hero
// ─────────────────────────────────────────────────────────────────────────────

function Hero() {
	return (
		<section className="relative border-b border-border/60">
			{/* Background dot grid */}
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
						<span className="tabular-nums">§01</span>
						<span className="h-3 w-px bg-primary-foreground/40" aria-hidden />
						<span>Federation · v0.1.0 pre-release</span>
					</div>

					<h1 className="mt-6 font-heading text-[40px] font-bold leading-[1.02] tracking-[-0.03em] text-balance sm:text-[56px] lg:text-[68px] xl:text-[76px]">
						<span className="block">OpenID Federation&nbsp;1.0</span>
						<span className="block bg-gradient-to-r from-brand-600 via-brand-500 to-brand-300 bg-clip-text text-transparent dark:from-brand-300 dark:via-brand-400 dark:to-brand-500">
							for&nbsp;JavaScript.
						</span>
					</h1>

					<p className="mt-6 max-w-xl text-lg leading-relaxed text-muted-foreground text-balance">
						The complete OpenID Federation 1.0 implementation for JavaScript — runtime-agnostic,
						spec-compliant, built on Web API standards.
					</p>

					<p className="mt-4 max-w-xl text-[15px] leading-relaxed text-muted-foreground/80">
						Trust Anchors, Entity Configurations, Trust Chains, Subordinate Statements, Metadata
						Policy, Trust Marks, authority hints, federation endpoints, and automatic / explicit
						client registration — wired as{" "}
						<code className="rounded-sm bg-muted px-1.5 py-0.5 font-mono text-[13px] tracking-tight text-foreground">
							(Request) =&gt; Promise&lt;Response&gt;
						</code>{" "}
						handlers that run identically on Node.js, Deno, Bun, workerd, Electron, and browsers.
					</p>

					{/* CTAs */}
					<div className="mt-10 flex flex-wrap items-center gap-3">
						<a
							href="https://explore.oidfed.com"
							target="_blank"
							rel="noopener noreferrer"
							className={`${buttonVariants()} group`}
						>
							Open the Explorer
							<ArrowUpRight className="ml-1.5 size-4 transition-transform group-hover:-translate-y-0.5 group-hover:translate-x-0.5" />
						</a>
						<a
							href="https://learn.oidfed.com"
							target="_blank"
							rel="noopener noreferrer"
							className={buttonVariants({ variant: "outline" })}
						>
							Learn OpenID Federation
						</a>
						<div className="ml-auto flex items-center gap-1 sm:ml-0">
							<a
								href="https://github.com/Dahkenangnon/oidfed"
								target="_blank"
								rel="noopener noreferrer"
								aria-label="View source on GitHub"
								className="inline-flex h-9 w-9 items-center justify-center rounded-md border border-border text-muted-foreground transition-colors hover:border-foreground/30 hover:text-foreground"
							>
								<GitHubGlyph />
							</a>
							<a
								href="https://www.npmjs.com/org/oidfed"
								target="_blank"
								rel="noopener noreferrer"
								aria-label="View packages on npm"
								className="inline-flex h-9 items-center gap-1.5 rounded-md border border-border px-3 font-mono text-[11px] font-medium uppercase tracking-wider text-muted-foreground transition-colors hover:border-foreground/30 hover:text-foreground"
							>
								<NpmGlyph /> npm
							</a>
						</div>
					</div>

					{/* Meta row */}
					<div className="mt-10 flex flex-wrap items-center gap-x-6 gap-y-2 font-mono text-[11px] uppercase tracking-[0.16em] text-muted-foreground">
						<span className="flex items-center gap-1.5">
							<span className="inline-block size-1.5 rounded-full bg-emerald-500" />
							MIT licensed
						</span>
						<span className="flex items-center gap-1.5">
							<span className="inline-block size-1.5 rounded-full bg-brand-500" />6 runtimes
						</span>
					</div>
				</div>

				{/* Right — federation graph */}
				<div className="relative fade-rise delay-2">
					<div className="relative rounded-2xl border border-border/60 bg-card/40 p-4 shadow-sm backdrop-blur-sm sm:p-6">
						{/* Window chrome */}
						<div className="mb-4 flex items-center justify-between border-b border-border/60 pb-3">
							<div className="flex items-center gap-1.5">
								<span className="size-2.5 rounded-full bg-red-400/70" aria-hidden />
								<span className="size-2.5 rounded-full bg-amber-400/70" aria-hidden />
								<span className="size-2.5 rounded-full bg-emerald-400/70" aria-hidden />
							</div>
							<span className="font-mono text-[10px] uppercase tracking-[0.2em] text-muted-foreground">
								resolve.trust.chain
							</span>
							<span className="font-mono text-[10px] tabular-nums text-muted-foreground/70">
								ES256
							</span>
						</div>
						<div className="relative">
							<HeroFederationGraph />
							<ResolvedStatus />
						</div>
					</div>

					{/* Caption */}
					<p className="mt-3 pl-2 font-mono text-[10.5px] uppercase tracking-[0.22em] text-muted-foreground/80">
						ta.example.org → op-1.example.com · resolved in 320ms
					</p>
				</div>
			</div>
		</section>
	);
}

function GitHubGlyph() {
	return (
		<svg
			viewBox="0 0 16 16"
			className="size-4"
			aria-hidden="true"
			role="presentation"
			fill="currentColor"
		>
			<path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z" />
		</svg>
	);
}

function NpmGlyph() {
	return (
		<svg
			viewBox="0 0 16 16"
			className="size-3.5"
			aria-hidden="true"
			role="presentation"
			fill="currentColor"
		>
			<path d="M0 2v12h4.667V5.333h2.666V14H16V2H0zm8.667 1.333H14v9.334h-2.667V4.667H9.333v8H8.667V3.333z" />
		</svg>
	);
}

// ─────────────────────────────────────────────────────────────────────────────
// §02 · Why Federation
// ─────────────────────────────────────────────────────────────────────────────

function WhyFederation() {
	return (
		<section className="border-b border-border/60 bg-muted/30">
			<div className="mx-auto grid max-w-6xl gap-12 px-6 py-20 lg:grid-cols-[1fr_1.4fr] lg:gap-20 lg:py-28">
				{/* Left column — sticky intro */}
				<div className="lg:sticky lg:top-24 lg:self-start">
					<SignalLabel id="02" label="Why Federation" />
					<h2 className="mt-6 font-heading text-3xl font-semibold tracking-[-0.02em] text-balance sm:text-4xl">
						Trust, unbundled from bilateral agreements.
					</h2>
					<p className="mt-5 text-[15px] leading-relaxed text-muted-foreground">
						Traditional approaches to establishing trust between systems rely on bilateral
						agreements and manual metadata exchange. OpenID Federation introduces cryptographically
						verifiable trust chains — enabling dynamic, scalable trust without per-party
						configuration.
					</p>
					<div className="mt-6 inline-flex items-center gap-3 font-mono text-[11px] uppercase tracking-[0.16em] text-muted-foreground">
						<span className="tabular-nums text-foreground">N²</span>
						<ArrowRight className="size-3" />
						<span className="tabular-nums text-foreground">O(depth)</span>
					</div>
				</div>

				{/* Right column — numbered rows */}
				<ol className="space-y-0">
					{whyReasons.map((r, i) => {
						const Icon = r.Icon;
						return (
							<li
								key={r.title}
								className="group relative grid grid-cols-[auto_1fr] gap-x-6 gap-y-2 border-t border-border/60 py-8 first:border-t-0 sm:grid-cols-[110px_1fr] sm:gap-x-8"
							>
								<span
									aria-hidden
									className="font-heading text-5xl font-bold tabular-nums tracking-[-0.04em] text-muted-foreground/30 transition-colors duration-500 group-hover:text-brand-500 sm:text-[64px]"
								>
									{String(i + 1).padStart(2, "0")}
								</span>
								<div className="min-w-0">
									<div className="flex items-center gap-2">
										<Icon className="size-4 text-brand-500" aria-hidden />
										<h3 className="font-heading text-lg font-semibold tracking-tight sm:text-xl">
											{r.title}
										</h3>
									</div>
									<p className="mt-3 max-w-prose text-[15px] leading-relaxed text-muted-foreground">
										{r.body}
									</p>
								</div>
							</li>
						);
					})}
				</ol>
			</div>
		</section>
	);
}

// ─────────────────────────────────────────────────────────────────────────────
// §03 · What's Inside
// ─────────────────────────────────────────────────────────────────────────────

function WhatsInside() {
	return (
		<section className="border-b border-border/60">
			<div className="mx-auto max-w-6xl px-6 py-20 lg:py-28">
				<div className="flex flex-col items-start justify-between gap-6 sm:flex-row sm:items-end">
					<div>
						<SignalLabel id="03" label="What's Inside" />
						<h2 className="mt-6 font-heading text-3xl font-semibold tracking-[-0.02em] text-balance sm:text-4xl">
							Four spec packages, three apps, one CLI.
						</h2>
						<p className="mt-4 max-w-xl text-[15px] leading-relaxed text-muted-foreground">
							Modular by design. Install only what you need — from core primitives to full OIDC
							registration flows, interactive learning, and visual exploration tools.
						</p>
					</div>
					<div className="flex flex-wrap items-center gap-2">
						<Badge variant="secondary" className="font-mono text-[11px]">
							TypeScript
						</Badge>
						<Badge variant="secondary" className="font-mono text-[11px]">
							Runtime-agnostic
						</Badge>
						<Badge variant="secondary" className="font-mono text-[11px]">
							Web&nbsp;API
						</Badge>
					</div>
				</div>

				{/* Packages — table layout */}
				<div className="mt-12">
					<div className="flex items-center gap-3 font-mono text-[11px] uppercase tracking-[0.18em] text-muted-foreground">
						<Package className="size-3.5" />
						Spec implementation
						<span className="h-px flex-1 bg-border" />
						<span className="tabular-nums">{specPackages.length} packages</span>
					</div>

					<ul className="mt-5 divide-y divide-border/60 rounded-xl border border-border/60 bg-card/40">
						{specPackages.map((pkg) => (
							<li key={pkg.name}>
								<a
									href={pkg.href}
									target="_blank"
									rel="noopener noreferrer"
									className="group grid grid-cols-1 gap-2 p-5 transition-colors hover:bg-muted/50 sm:grid-cols-[minmax(220px,1fr)_2fr_auto] sm:items-center sm:gap-6"
								>
									<div>
										<div className="font-mono text-[14px] font-semibold tracking-tight text-foreground">
											{pkg.name}
										</div>
										<div className="mt-1 font-mono text-[11px] text-muted-foreground/70">
											<span className="text-brand-500">$</span> {pkg.install}
										</div>
									</div>
									<p className="text-[14px] leading-relaxed text-muted-foreground">
										{pkg.description}
									</p>
									<div className="text-brand-500 opacity-0 transition-opacity group-hover:opacity-100">
										<ArrowUpRight className="size-4" />
									</div>
								</a>
							</li>
						))}
					</ul>
				</div>

				{/* Apps — differentiated cards */}
				<div className="mt-16">
					<div className="flex items-center gap-3 font-mono text-[11px] uppercase tracking-[0.18em] text-muted-foreground">
						<Globe className="size-3.5" />
						Apps
						<span className="h-px flex-1 bg-border" />
						<span className="tabular-nums">{apps.length} surfaces</span>
					</div>

					<div className="mt-5 grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
						{apps.map((app) => (
							<a
								key={app.name}
								href={app.href}
								target="_blank"
								rel="noopener noreferrer"
								className="group block"
							>
								<Card className="flex h-full flex-col overflow-hidden transition-all group-hover:-translate-y-0.5 group-hover:border-brand-500/40 group-hover:shadow-md">
									{/* Preview tile */}
									<div className="relative aspect-[2/1] bg-muted/50">
										<AppPreview kind={app.preview} />
									</div>
									<div className="flex flex-1 flex-col gap-3 p-5">
										<div className="flex items-center justify-between">
											<CardTitle className="font-mono text-[13px]">{app.name}</CardTitle>
											<span className="rounded-sm bg-muted px-1.5 py-0.5 font-mono text-[9px] font-semibold uppercase tracking-wider text-muted-foreground">
												{app.label}
											</span>
										</div>
										<p className="text-[13px] leading-relaxed text-muted-foreground">
											{app.description}
										</p>
										<div className="mt-auto flex items-center gap-1 pt-2 text-[12px] font-medium text-brand-500">
											<span className="font-mono">{app.href.replace(/^https?:\/\//, "")}</span>
											<ArrowUpRight className="size-3 transition-transform group-hover:-translate-y-0.5 group-hover:translate-x-0.5" />
										</div>
									</div>
								</Card>
							</a>
						))}
					</div>
				</div>

				{/* CLI — terminal card */}
				<div className="mt-16">
					<div className="flex items-center gap-3 font-mono text-[11px] uppercase tracking-[0.18em] text-muted-foreground">
						<Terminal className="size-3.5" />
						Tools
						<span className="h-px flex-1 bg-border" />
					</div>

					<a
						href="https://www.npmjs.com/package/@oidfed/cli"
						target="_blank"
						rel="noopener noreferrer"
						className="group mt-5 block"
					>
						<div className="overflow-hidden rounded-xl border border-border/60 bg-card/40 transition-all group-hover:-translate-y-0.5 group-hover:border-brand-500/40 group-hover:shadow-md">
							<div className="grid gap-0 sm:grid-cols-[1fr_1px_1.4fr]">
								<div className="flex flex-col gap-3 p-6 sm:p-7">
									<div className="flex items-center gap-2">
										<Terminal className="size-4 text-brand-500" />
										<CardTitle className="font-mono text-[14px]">@oidfed/cli</CardTitle>
										<span className="ml-auto rounded-sm bg-muted px-1.5 py-0.5 font-mono text-[9px] font-semibold uppercase tracking-wider text-muted-foreground">
											14 commands
										</span>
									</div>
									<p className="text-[14px] leading-relaxed text-muted-foreground">
										Command-line interface for inspecting, validating, and debugging OpenID
										Federation deployments — resolve trust chains, decode entity statements, verify
										signatures.
									</p>
									<div className="mt-auto flex items-center gap-1 text-[12px] font-medium text-brand-500">
										<span className="font-mono">npm install -g @oidfed/cli</span>
										<ArrowUpRight className="size-3 transition-transform group-hover:-translate-y-0.5 group-hover:translate-x-0.5" />
									</div>
								</div>
								<div aria-hidden className="hidden bg-border/60 sm:block" />
								<div className="bg-[oklch(0.18_0.015_250)] p-6 font-mono text-[12.5px] leading-relaxed text-slate-200 sm:p-7 dark:bg-[oklch(0.14_0.015_250)]">
									<div className="flex gap-2">
										<span className="text-slate-500">$</span>
										<span className="text-brand-300">oidfed</span> <span>resolve</span>{" "}
										https://op-1.example.com
									</div>
									<div className="mt-3 text-slate-400">
										<span className="text-emerald-400">✓</span> Entity Configuration fetched
									</div>
									<div className="text-slate-400">
										<span className="text-emerald-400">✓</span> Trust chain assembled (3 statements)
									</div>
									<div className="text-slate-400">
										<span className="text-emerald-400">✓</span> Metadata policy applied
									</div>
									<div className="mt-3">
										<span className="text-slate-500"># trust_anchor: </span>
										<span className="text-brand-300">ta.example.org</span>
									</div>
									<div>
										<span className="text-slate-500"># expires_in: </span>
										<span className="text-amber-300">23h 47m</span>
									</div>
								</div>
							</div>
						</div>
					</a>
				</div>
			</div>
		</section>
	);
}

// ─────────────────────────────────────────────────────────────────────────────
// §04 · In Production
// ─────────────────────────────────────────────────────────────────────────────

function InProduction() {
	return (
		<section className="border-b border-border/60 bg-muted/30">
			<div className="mx-auto max-w-6xl px-6 py-20 lg:py-28">
				<div className="flex flex-col items-start justify-between gap-6 sm:flex-row sm:items-end">
					<div>
						<SignalLabel id="04" label="Where OpenID Federation is being adopted" />
						<h2 className="mt-6 font-heading text-3xl font-semibold tracking-[-0.02em] text-balance sm:text-4xl">
							Named adoptions, pilots, and specifications.
						</h2>
						<p className="mt-4 max-w-xl text-[15px] leading-relaxed text-muted-foreground">
							Examples of OpenID Federation being adopted, piloted, or specified for trust
							establishment across governments, academic networks, and AI-agent identity research.
							Status varies — from published technical rules to running pilots. Every entry links
							to an authoritative source.
						</p>
					</div>
					<div className="rounded-xl border border-border/60 bg-card/40 px-4 py-3 font-mono text-[10.5px] uppercase tracking-[0.18em] text-muted-foreground">
						<div className="text-foreground">OpenID Federation 1.0</div>
						<div className="mt-1 flex items-center gap-1.5 text-brand-500">
							<span className="inline-block size-1.5 rounded-full bg-brand-500" aria-hidden />
							Final · Feb 2026
						</div>
					</div>
				</div>

				<ul className="mt-12 divide-y divide-border/60 rounded-xl border border-border/60 bg-card/40">
					{adopters.map((a) => (
						<li key={a.name}>
							<a
								href={a.href}
								target="_blank"
								rel="noopener noreferrer"
								className="group grid grid-cols-[auto_1fr_auto] items-center gap-4 p-5 transition-colors hover:bg-muted/50 sm:grid-cols-[auto_minmax(240px,1fr)_2fr_auto] sm:gap-6"
							>
								<CountryFlag region={a.region} />
								<div className="min-w-0">
									<div className="flex items-center gap-2">
										<span className="font-heading text-[16px] font-semibold tracking-tight">
											{a.name}
										</span>
									</div>
									<div className="mt-1 font-mono text-[10.5px] uppercase tracking-[0.16em] text-muted-foreground">
										{a.tag}
									</div>
								</div>
								<p className="hidden text-[13px] leading-relaxed text-muted-foreground sm:block">
									{a.detail}
								</p>
								<ExternalLink className="size-4 text-muted-foreground transition-colors group-hover:text-brand-500" />
							</a>
						</li>
					))}
				</ul>

				<Link
					to="/ecosystem"
					className="group mt-6 inline-flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-[0.18em] text-brand-500 transition-colors hover:text-brand-600"
				>
					See the full ecosystem
					<ArrowRight className="size-3 transition-transform group-hover:translate-x-0.5" />
				</Link>
			</div>
		</section>
	);
}

// ─────────────────────────────────────────────────────────────────────────────
// §05 · AI & Machine Identity (closer)
// ─────────────────────────────────────────────────────────────────────────────

function MachineIdentity() {
	return (
		<section className="relative overflow-hidden border-b border-border/60">
			{/* Decorative gradient */}
			<div
				aria-hidden
				className="pointer-events-none absolute inset-0 -z-10 bg-gradient-to-br from-brand-500/5 via-transparent to-brand-500/10 dark:from-brand-500/10 dark:to-brand-500/15"
			/>
			{/* Decorative graph lines */}
			<svg
				className="pointer-events-none absolute -right-20 -top-20 h-[320px] w-[320px] text-brand-500 opacity-[0.15] sm:h-[420px] sm:w-[420px] sm:-right-10 sm:-top-10"
				viewBox="0 0 420 420"
				aria-hidden="true"
				role="presentation"
			>
				<defs>
					<pattern id="mi-dots" x="0" y="0" width="20" height="20" patternUnits="userSpaceOnUse">
						<circle cx="1" cy="1" r="0.8" fill="currentColor" />
					</pattern>
				</defs>
				<circle cx="210" cy="210" r="200" fill="none" stroke="currentColor" strokeWidth="0.5" />
				<circle cx="210" cy="210" r="140" fill="none" stroke="currentColor" strokeWidth="0.5" />
				<circle cx="210" cy="210" r="80" fill="none" stroke="currentColor" strokeWidth="0.5" />
				<rect width="420" height="420" fill="url(#mi-dots)" />
			</svg>

			<div className="mx-auto max-w-6xl px-6 py-20 lg:py-28">
				<div className="max-w-3xl">
					<SignalLabel id="05" label="AI & Machine Identity" />
					<h2 className="mt-6 font-heading text-3xl font-semibold tracking-[-0.02em] text-balance sm:text-4xl lg:text-[44px]">
						Verifiable trust for{" "}
						<span className="bg-gradient-to-r from-brand-600 to-brand-400 bg-clip-text text-transparent dark:from-brand-300 dark:to-brand-500">
							agent-to-agent
						</span>{" "}
						futures.
					</h2>
					<p className="mt-6 text-[16px] leading-relaxed text-muted-foreground">
						As AI agents interact on behalf of users and organizations, verifiable trust becomes
						critical. OpenID Federation provides the infrastructure for agent-to-agent trust —
						machines can verify each other's identity and capabilities through the same
						cryptographic trust chains that today secure humans, applications, and services.
					</p>
					<p className="mt-4 text-[15px] leading-relaxed text-muted-foreground/85">
						The same Trust Anchors, Entity Configurations, Subordinate Statements, Metadata Policy,
						and Trust Marks that bind humans into a federation can bind autonomous agents into a
						federation of machines — with cryptographically enforceable limits on what any given
						agent is authorised to do on whose behalf.
					</p>
					<p className="mt-4 text-[13.5px] leading-relaxed text-muted-foreground/75">
						The OpenID Foundation's AI Identity Management Community Group has published a{" "}
						<a
							href="https://openid.net/new-whitepaper-tackles-ai-agent-identity-challenges/"
							target="_blank"
							rel="noopener noreferrer"
							className="underline underline-offset-[3px] transition-colors hover:text-foreground"
						>
							whitepaper
						</a>{" "}
						(
						<a
							href="https://openid.net/wp-content/uploads/2025/10/Identity-Management-for-Agentic-AI.pdf"
							target="_blank"
							rel="noopener noreferrer"
							className="underline underline-offset-[3px] transition-colors hover:text-foreground"
						>
							PDF
						</a>
						) naming OpenID Federation as a candidate trust fabric for agent-to-agent identity.
					</p>
				</div>
			</div>
		</section>
	);
}
