import { Badge, Card, CardHeader, CardPanel, CardTitle } from "@oidfed/ui";
import { AnalogyBox } from "~/components/analogy-box";
import { Ref, SourcesSection } from "~/components/footnote";
import { JsonExplorer } from "~/components/json-explorer";
import { LessonPage } from "~/components/lesson-page";
import { StepThrough } from "~/components/step-through";
import { ToggleView } from "~/components/toggle-view";
import { getLesson } from "~/data/lessons";

export const handle = { lastUpdated: "2026-04-20" };

export function meta() {
	return [
		{ title: "Trust Marks — Learn OpenID Federation" },
		{
			name: "description",
			content:
				"Certified badges that prove an entity meets specific requirements in OpenID Federation.",
		},
		{ name: "author", content: "Justin Dah-kenangnon" },
		{ property: "og:title", content: "Trust Marks" },
		{
			property: "og:description",
			content: "Trust Mark issuance, delegation, and validation explained.",
		},
		{ property: "og:type", content: "article" },
		{ property: "article:author", content: "https://dahkenangnon.com" },
		{ property: "article:section", content: "Advanced" },
	];
}

const trustMarkJwt = {
	header: { alg: "RS256", typ: "trust-mark+jwt", kid: "tm-key-1" },
	payload: {
		iss: "https://audit-body.example.com",
		sub: "https://login.uni.edu",
		trust_mark_type: "https://edufed.gov/trust-marks/gdpr",
		iat: 1712000000,
		exp: 1743536000,
		logo_uri: "https://edufed.gov/badges/gdpr.png",
		ref: "https://edufed.gov/compliance/gdpr-requirements",
	},
};

const delegationSteps = [
	{
		title: "1. TA defines Trust Mark type",
		content: (
			<p className="text-sm">
				The Trust Anchor defines a Trust Mark type (e.g.,{" "}
				<code>https://edufed.gov/trust-marks/gdpr</code>) and declares who may issue it via{" "}
				<code>trust_mark_issuers</code> and/or <code>trust_mark_owners</code> in its Entity
				Configuration.
				<Ref id="1" />
			</p>
		),
	},
	{
		title: "2. Trust Mark Owner creates delegation",
		content: (
			<p className="text-sm">
				The Trust Mark Owner creates a Delegation JWT granting an audit body permission to issue
				this specific Trust Mark type on its behalf.
				<Ref id="2" />
			</p>
		),
	},
	{
		title: "3. Delegated Issuer evaluates entity",
		content: (
			<p className="text-sm">
				The delegated issuer (audit body) evaluates the entity against the requirements for the
				Trust Mark — e.g., GDPR compliance audit.
			</p>
		),
	},
	{
		title: "4. Delegated Issuer signs Trust Mark JWT",
		content: (
			<p className="text-sm">
				If the entity passes, the delegated issuer signs a Trust Mark JWT, embedding the delegation
				JWT as proof of authorization.
			</p>
		),
	},
	{
		title: "5. Entity includes Trust Mark in EC",
		content: (
			<p className="text-sm">
				The entity adds the Trust Mark to its <code>trust_marks</code> array in its Entity
				Configuration. Anyone resolving this entity's trust chain can now see and verify the mark.
			</p>
		),
	},
];

function ValidationResult({ scenario }: { scenario: "valid" | "expired" | "revoked" }) {
	const checks = [
		{ label: "1. Verify JWT signature", pass: true },
		{ label: "2. Is issuer trusted? (trust_mark_issuers)", pass: true },
		{ label: "3. Verify delegation JWT (if present)", pass: true },
		{ label: "4. Check exp — still valid?", pass: scenario !== "expired" },
		{ label: "5. Call Trust Mark Status endpoint", pass: scenario !== "revoked" },
	];
	return (
		<div className="space-y-2">
			{checks.map((c, i) => {
				const failed = !c.pass;
				const skipped = i > 0 && !checks[i - 1]?.pass;
				return (
					<div
						key={c.label}
						className={`flex items-center gap-2 text-sm ${skipped ? "opacity-30" : ""}`}
					>
						<span className={failed ? "text-red-500" : "text-emerald-500"}>
							{failed ? "✗" : "✓"}
						</span>
						<span>{c.label}</span>
						{failed && (
							<Badge variant="destructive" size="sm">
								FAIL
							</Badge>
						)}
					</div>
				);
			})}
			<p
				className={`text-sm font-semibold mt-2 ${scenario === "valid" ? "text-emerald-600" : "text-red-500"}`}
			>
				{scenario === "valid" && "Trust Mark is VALID"}
				{scenario === "expired" && "Trust Mark is EXPIRED — rejected at step 4"}
				{scenario === "revoked" && "Trust Mark is REVOKED — status endpoint returned 'revoked'"}
			</p>
		</div>
	);
}

export default function Lesson07() {
	return (
		<LessonPage lesson={getLesson(7)}>
			<h2>What's Inside a Trust Mark?</h2>
			<p>
				A Trust Mark is a signed JWT
				<Ref id="1" /> that certifies an entity meets specific requirements — like a health
				inspection sticker for digital identity. It contains the issuer, subject, type, and optional
				metadata like logos and reference URLs.
			</p>
			<JsonExplorer data={trustMarkJwt} />

			<h2>Who Can Issue Trust Marks?</h2>
			<div className="grid gap-3 sm:grid-cols-2 my-4">
				{[
					{
						title: "Trust Anchors",
						desc: "Can issue directly — they define the trust mark types.",
					},
					{
						title: "Authorized Issuers",
						desc: "Listed in trust_mark_issuers in the TA's Entity Configuration.",
					},
					{
						title: "Delegated Issuers",
						desc: "Authorized by a Trust Mark Owner via a delegation JWT.",
					},
					{ title: "Self-Signed", desc: "The federation MAY allow entities to self-issue (rare)." },
				].map((item) => (
					<Card key={item.title}>
						<CardHeader className="pb-1">
							<CardTitle className="text-sm">{item.title}</CardTitle>
						</CardHeader>
						<CardPanel className="pt-0 text-sm text-muted-foreground">{item.desc}</CardPanel>
					</Card>
				))}
			</div>

			<h2>Delegation Flow</h2>
			<StepThrough steps={delegationSteps} />

			<h2>Validating a Trust Mark</h2>
			<p>
				Validation involves 5 checks
				<Ref id="3" /> — a failure at any step rejects the mark:
			</p>
			<ToggleView
				labelA="Valid Mark"
				labelB="Expired Mark"
				contentA={<ValidationResult scenario="valid" />}
				contentB={<ValidationResult scenario="expired" />}
			/>

			<AnalogyBox>
				Think of a safety certification sticker on an elevator. An authorized inspector examines it,
				issues a signed certificate, the building owner displays it, and anyone can check with the
				certification authority to confirm it's still valid.
			</AnalogyBox>

			<SourcesSection
				sources={[
					{
						id: "1",
						text: "OpenID Federation 1.0, Section 7.1 — Trust Mark Claims",
						url: "https://openid.net/specs/openid-federation-1_0.html#section-7.1",
					},
					{
						id: "2",
						text: "OpenID Federation 1.0, Section 7.2 — Trust Mark Delegation",
						url: "https://openid.net/specs/openid-federation-1_0.html#section-7.2",
					},
					{
						id: "3",
						text: "OpenID Federation 1.0, Section 7.3 — Validating a Trust Mark",
						url: "https://openid.net/specs/openid-federation-1_0.html#section-7.3",
					},
				]}
			/>
		</LessonPage>
	);
}
