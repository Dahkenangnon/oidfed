import { AnalogyBox } from "~/components/analogy-box";
import { Ref, SourcesSection } from "~/components/footnote";
import { LessonPage } from "~/components/lesson-page";
import { TermCard } from "~/components/term-card";
import { ToggleView } from "~/components/toggle-view";
import { getLesson } from "~/data/lessons";

export const handle = { lastUpdated: "2026-04-20" };

export function meta() {
	return [
		{ title: "What is OpenID Federation? — Learn OpenID Federation" },
		{
			name: "description",
			content:
				"Learn why OpenID Federation exists, what problem it solves, and how it turns an N-squared trust problem into a scalable hierarchy.",
		},
		{ name: "author", content: "Justin Dah-kenangnon" },
		{ property: "og:title", content: "What is OpenID Federation?" },
		{
			property: "og:description",
			content: "Understanding the problem federation solves and why it matters.",
		},
		{ property: "og:type", content: "article" },
		{ property: "article:author", content: "https://dahkenangnon.com" },
		{ property: "article:section", content: "Foundation" },
	];
}

function ChaosSvg() {
	const apps = [
		{ x: 60, y: 40, label: "App 1" },
		{ x: 200, y: 30, label: "App 2" },
		{ x: 340, y: 50, label: "App 3" },
		{ x: 130, y: 130, label: "App 4" },
		{ x: 270, y: 120, label: "App 5" },
	];
	const idps = [
		{ x: 80, y: 220, label: "IdP 1" },
		{ x: 190, y: 240, label: "IdP 2" },
		{ x: 300, y: 210, label: "IdP 3" },
		{ x: 240, y: 280, label: "IdP 4" },
	];
	return (
		<svg
			viewBox="0 0 400 320"
			className="w-full max-w-md mx-auto"
			role="img"
			aria-labelledby="chaos-title"
		>
			<title id="chaos-title">Without federation: chaotic connections</title>
			{apps.map((a) =>
				idps.map((idp) => (
					<line
						key={`${a.label}-${idp.label}`}
						x1={a.x}
						y1={a.y}
						x2={idp.x}
						y2={idp.y}
						stroke="var(--color-red-400)"
						strokeWidth="1"
						opacity="0.5"
					/>
				)),
			)}
			{apps.map((a) => (
				<g key={a.label}>
					<circle
						cx={a.x}
						cy={a.y}
						r="18"
						className="fill-red-100 dark:fill-red-900/40 stroke-red-400"
						strokeWidth="2"
					/>
					<text
						x={a.x}
						y={a.y + 4}
						textAnchor="middle"
						className="fill-foreground text-[10px] font-medium"
					>
						{a.label}
					</text>
				</g>
			))}
			{idps.map((idp) => (
				<g key={idp.label}>
					<circle
						cx={idp.x}
						cy={idp.y}
						r="18"
						className="fill-red-100 dark:fill-red-900/40 stroke-red-400"
						strokeWidth="2"
					/>
					<text
						x={idp.x}
						y={idp.y + 4}
						textAnchor="middle"
						className="fill-foreground text-[10px] font-medium"
					>
						{idp.label}
					</text>
				</g>
			))}
			<text x="200" y="310" textAnchor="middle" className="fill-muted-foreground text-xs">
				Without Federation — Every entity connects to every other (N x N)
			</text>
		</svg>
	);
}

function FederationSvg() {
	return (
		<svg
			viewBox="0 0 400 320"
			className="w-full max-w-md mx-auto"
			role="img"
			aria-labelledby="federation-title"
		>
			<title id="federation-title">With federation: organized hierarchy</title>
			{/* Lines */}
			<line x1="200" y1="50" x2="120" y2="120" stroke="var(--color-emerald-500)" strokeWidth="2" />
			<line x1="200" y1="50" x2="280" y2="120" stroke="var(--color-emerald-500)" strokeWidth="2" />
			<line x1="120" y1="120" x2="60" y2="200" stroke="var(--color-emerald-500)" strokeWidth="2" />
			<line x1="120" y1="120" x2="160" y2="200" stroke="var(--color-emerald-500)" strokeWidth="2" />
			<line x1="280" y1="120" x2="240" y2="200" stroke="var(--color-emerald-500)" strokeWidth="2" />
			<line x1="280" y1="120" x2="340" y2="200" stroke="var(--color-emerald-500)" strokeWidth="2" />
			<line x1="60" y1="200" x2="40" y2="270" stroke="var(--color-emerald-500)" strokeWidth="2" />
			<line x1="60" y1="200" x2="90" y2="270" stroke="var(--color-emerald-500)" strokeWidth="2" />
			<line x1="240" y1="200" x2="220" y2="270" stroke="var(--color-emerald-500)" strokeWidth="2" />
			<line x1="340" y1="200" x2="320" y2="270" stroke="var(--color-emerald-500)" strokeWidth="2" />
			<line x1="340" y1="200" x2="370" y2="270" stroke="var(--color-emerald-500)" strokeWidth="2" />
			{/* Trust Anchor */}
			<circle
				cx="200"
				cy="50"
				r="22"
				className="fill-brand-100 dark:fill-brand-900/40 stroke-brand-500"
				strokeWidth="2"
			/>
			<text x="200" y="54" textAnchor="middle" className="fill-foreground text-[9px] font-semibold">
				Trust Anchor
			</text>
			{/* Intermediates */}
			{[
				{ x: 120, y: 120 },
				{ x: 280, y: 120 },
			].map((p, i) => (
				// biome-ignore lint/suspicious/noArrayIndexKey: SVG nodes have no stable key
				<g key={i}>
					<circle
						cx={p.x}
						cy={p.y}
						r="18"
						className="fill-emerald-100 dark:fill-emerald-900/40 stroke-emerald-500"
						strokeWidth="2"
					/>
					<text
						x={p.x}
						y={p.y + 4}
						textAnchor="middle"
						className="fill-foreground text-[9px] font-medium"
					>
						IA {i + 1}
					</text>
				</g>
			))}
			{/* Leaves */}
			{[
				{ x: 60, y: 200, l: "OP 1" },
				{ x: 160, y: 200, l: "OP 2" },
				{ x: 240, y: 200, l: "RP 1" },
				{ x: 340, y: 200, l: "RP 2" },
			].map((n) => (
				<g key={n.l}>
					<circle
						cx={n.x}
						cy={n.y}
						r="16"
						className="fill-purple-100 dark:fill-purple-900/40 stroke-purple-500"
						strokeWidth="2"
					/>
					<text
						x={n.x}
						y={n.y + 4}
						textAnchor="middle"
						className="fill-foreground text-[9px] font-medium"
					>
						{n.l}
					</text>
				</g>
			))}
			{/* Apps */}
			{[
				{ x: 40, y: 270, l: "App 1" },
				{ x: 90, y: 270, l: "App 2" },
				{ x: 220, y: 270, l: "App 3" },
				{ x: 320, y: 270, l: "App 4" },
				{ x: 370, y: 270, l: "App 5" },
			].map((n) => (
				<g key={n.l}>
					<circle
						cx={n.x}
						cy={n.y}
						r="14"
						className="fill-amber-100 dark:fill-amber-900/40 stroke-amber-500"
						strokeWidth="2"
					/>
					<text
						x={n.x}
						y={n.y + 4}
						textAnchor="middle"
						className="fill-foreground text-[8px] font-medium"
					>
						{n.l}
					</text>
				</g>
			))}
			<text x="200" y="310" textAnchor="middle" className="fill-muted-foreground text-xs">
				With Federation — Clean hierarchy, shared trust
			</text>
		</svg>
	);
}

export default function Lesson01() {
	return (
		<LessonPage lesson={getLesson(1)}>
			<h2>The Problem</h2>
			<p>
				Imagine a world where every application that needs to verify a user's identity must
				establish a direct, individual relationship with every identity provider. With 5 apps and 4
				identity providers, that's 20 separate connections to configure, secure, and maintain.
				<Ref id="1" /> As the ecosystem grows, the number of bilateral relationships explodes — it's
				an <strong>N &times; N problem</strong>.
			</p>
			<p>
				OpenID Federation solves this by introducing a <strong>trust hierarchy</strong>.
				<Ref id="2" /> Instead of every entity connecting to every other, entities join a federation
				where trust is mediated by a <strong>Trust Anchor</strong> — a trusted third party at the
				top of the hierarchy. Intermediates can further delegate authority, creating a clean,
				scalable tree.
			</p>

			<h2>See the Difference</h2>
			<ToggleView
				labelA="Without Federation"
				labelB="With Federation"
				contentA={<ChaosSvg />}
				contentB={<FederationSvg />}
			/>

			<h2>Key Takeaway</h2>
			<p>
				Without federation, trust relationships grow as <strong>N &times; M</strong> (every app
				times every identity provider). With federation, entities only need to trust the hierarchy —
				turning it into a <strong>linear problem</strong>.<Ref id="3" />
			</p>

			<AnalogyBox>
				Think of international travel. Countries don't individually verify every traveler — they
				trust the <em>passport system</em>. Your country (Trust Anchor) issues your passport, and
				other countries trust that authority. Federation works the same way: entities trust the
				issuing authority rather than individually verifying every peer.
			</AnalogyBox>

			<h2>Key Terms Introduced</h2>
			<div className="grid gap-3 sm:grid-cols-2">
				<TermCard term="Multilateral Federation" section="Abstract">
					Federation where bilateral agreements are impractical; trust is mediated by a trusted
					third party.
				</TermCard>
				<TermCard term="Entity" section="Section 1.2">
					Something with separate and distinct existence that can be identified in a context.
				</TermCard>
				<TermCard term="Entity Identifier" section="Section 1.2">
					A globally unique URL using the <code>https</code> scheme. MAY contain port or path, MUST
					NOT contain query or fragment components.
				</TermCard>
				<TermCard term="Trust Anchor" section="Section 1.2">
					The top-level authority in a federation. Every Trust Chain ends at a Trust Anchor.
					Represents a trusted third party.
				</TermCard>
				<TermCard term="Trust" section="Section 1.2">
					Cryptographic assurance verified through signed statements up a chain of authority.
				</TermCard>
				<TermCard term="Scalability" section="Abstract">
					Federation turns the N-squared bilateral problem into a linear, hierarchical one.
				</TermCard>
			</div>

			<SourcesSection
				sources={[
					{
						id: "1",
						text: "OpenID Federation 1.0, Abstract — Multilateral Federation",
						url: "https://openid.net/specs/openid-federation-1_0.html#abstract",
					},
					{
						id: "2",
						text: "OpenID Federation 1.0, Section 1.2 — Terminology",
						url: "https://openid.net/specs/openid-federation-1_0.html#section-1.2",
					},
					{
						id: "3",
						text: "OpenID Federation 1.0, Section 4 — Trust Chain",
						url: "https://openid.net/specs/openid-federation-1_0.html#section-4",
					},
				]}
			/>
		</LessonPage>
	);
}
