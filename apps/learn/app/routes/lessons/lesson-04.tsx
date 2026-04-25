import { Badge } from "@oidfed/ui";
import { AnalogyBox } from "~/components/analogy-box";
import { Callout } from "~/components/callout";
import { LessonPage } from "~/components/lesson-page";
import { SpecRef } from "~/components/spec-ref";
import { StepThrough } from "~/components/step-through";
import { getLesson } from "~/data/lessons";

import { lessonMetaForSlug } from "~/lib/seo";
export const handle = { lastUpdated: "2026-04-25" };

export function meta() {
	return lessonMetaForSlug("trust-chains");
}

function ChainLink({
	index,
	label,
	issuer,
	subject,
	keyLabel,
	verified,
}: {
	index: number;
	label: string;
	issuer: string;
	subject: string;
	keyLabel: string;
	verified?: boolean;
}) {
	return (
		<div
			className={`rounded-lg border p-3 ${verified ? "border-emerald-500 bg-emerald-50 dark:bg-emerald-950/30" : "border-border bg-card"}`}
		>
			<div className="flex items-center gap-2 mb-1">
				<Badge variant={verified ? "success" : "secondary"} size="sm">
					[{index}]
				</Badge>
				<span className="font-semibold text-sm">{label}</span>
				{verified && <span className="text-emerald-600 text-xs">Verified</span>}
			</div>
			<div className="text-xs text-muted-foreground font-mono space-y-0.5">
				<div>iss: {issuer}</div>
				<div>sub: {subject}</div>
				<div>signed with: {keyLabel}</div>
			</div>
		</div>
	);
}

const buildSteps = [
	{
		title: "Step 1 — Leaf Entity Configuration",
		content: (
			<div className="space-y-3">
				<p className="text-sm">
					The leaf entity publishes its self-signed Entity Configuration at{" "}
					<code>.well-known/openid-federation</code>.
				</p>
				<ChainLink
					index={0}
					label="Leaf Entity Config"
					issuer="login.uni.edu"
					subject="login.uni.edu"
					keyLabel="K_leaf"
				/>
				<p className="text-xs text-muted-foreground">
					Self-signed: iss == sub. Contains authority_hints: ["uni.edu"]
				</p>
			</div>
		),
	},
	{
		title: "Step 2 — Subordinate Statement from Intermediate",
		content: (
			<div className="space-y-3">
				<p className="text-sm">
					The intermediate (uni.edu) vouches for the leaf by issuing a Subordinate Statement.
				</p>
				<ChainLink
					index={0}
					label="Leaf Entity Config"
					issuer="login.uni.edu"
					subject="login.uni.edu"
					keyLabel="K_leaf"
				/>
				<div className="text-center text-muted-foreground">↑</div>
				<ChainLink
					index={1}
					label="Sub. Stmt (Int → Leaf)"
					issuer="uni.edu"
					subject="login.uni.edu"
					keyLabel="K_intermediate"
				/>
				<p className="text-xs text-muted-foreground">
					Confirms K_leaf in jwks, may add metadata_policy.
				</p>
			</div>
		),
	},
	{
		title: "Step 3 — Trust Anchor vouches for Intermediate",
		content: (
			<div className="space-y-3">
				<p className="text-sm">
					The Trust Anchor issues a Subordinate Statement for the intermediate.
				</p>
				<ChainLink
					index={0}
					label="Leaf Entity Config"
					issuer="login.uni.edu"
					subject="login.uni.edu"
					keyLabel="K_leaf"
				/>
				<div className="text-center text-muted-foreground">↑</div>
				<ChainLink
					index={1}
					label="Sub. Stmt (Int → Leaf)"
					issuer="uni.edu"
					subject="login.uni.edu"
					keyLabel="K_intermediate"
				/>
				<div className="text-center text-muted-foreground">↑</div>
				<ChainLink
					index={2}
					label="Sub. Stmt (TA → Int)"
					issuer="edufed.gov"
					subject="uni.edu"
					keyLabel="K_ta"
				/>
			</div>
		),
	},
	{
		title: "Step 4 — Trust Anchor Configuration",
		content: (
			<div className="space-y-3">
				<p className="text-sm">
					The chain ends at the Trust Anchor's self-signed Entity Configuration.
				</p>
				<ChainLink
					index={0}
					label="Leaf Entity Config"
					issuer="login.uni.edu"
					subject="login.uni.edu"
					keyLabel="K_leaf"
				/>
				<div className="text-center text-muted-foreground">↑</div>
				<ChainLink
					index={1}
					label="Sub. Stmt (Int → Leaf)"
					issuer="uni.edu"
					subject="login.uni.edu"
					keyLabel="K_intermediate"
				/>
				<div className="text-center text-muted-foreground">↑</div>
				<ChainLink
					index={2}
					label="Sub. Stmt (TA → Int)"
					issuer="edufed.gov"
					subject="uni.edu"
					keyLabel="K_ta"
				/>
				<div className="text-center text-muted-foreground">↑</div>
				<ChainLink
					index={3}
					label="Trust Anchor Config"
					issuer="edufed.gov"
					subject="edufed.gov"
					keyLabel="K_ta (self)"
				/>
			</div>
		),
	},
	{
		title: "Step 5 — Verify from the top",
		content: (
			<div className="space-y-3">
				<p className="text-sm">Start verification with the pre-trusted Trust Anchor key (K_ta).</p>
				<ChainLink
					index={0}
					label="Leaf Entity Config"
					issuer="login.uni.edu"
					subject="login.uni.edu"
					keyLabel="K_leaf"
				/>
				<div className="text-center text-muted-foreground">↑</div>
				<ChainLink
					index={1}
					label="Sub. Stmt (Int → Leaf)"
					issuer="uni.edu"
					subject="login.uni.edu"
					keyLabel="K_intermediate"
				/>
				<div className="text-center text-muted-foreground">↑</div>
				<ChainLink
					index={2}
					label="Sub. Stmt (TA → Int)"
					issuer="edufed.gov"
					subject="uni.edu"
					keyLabel="K_ta"
				/>
				<div className="text-center text-muted-foreground">↑</div>
				<ChainLink
					index={3}
					label="Trust Anchor Config"
					issuer="edufed.gov"
					subject="edufed.gov"
					keyLabel="K_ta (self)"
					verified
				/>
				<p className="text-xs text-muted-foreground">
					Pre-trusted K_ta verifies [3]. K_ta from [3] then verifies [2].
				</p>
			</div>
		),
	},
	{
		title: "Step 6 — All links verified!",
		content: (
			<div className="space-y-3">
				<p className="text-sm">Each link reveals the key needed to verify the link below it.</p>
				<ChainLink
					index={0}
					label="Leaf Entity Config"
					issuer="login.uni.edu"
					subject="login.uni.edu"
					keyLabel="K_leaf"
					verified
				/>
				<div className="text-center text-emerald-500">↑ K_leaf</div>
				<ChainLink
					index={1}
					label="Sub. Stmt (Int → Leaf)"
					issuer="uni.edu"
					subject="login.uni.edu"
					keyLabel="K_intermediate"
					verified
				/>
				<div className="text-center text-emerald-500">↑ K_intermediate</div>
				<ChainLink
					index={2}
					label="Sub. Stmt (TA → Int)"
					issuer="edufed.gov"
					subject="uni.edu"
					keyLabel="K_ta"
					verified
				/>
				<div className="text-center text-emerald-500">↑ K_ta</div>
				<ChainLink
					index={3}
					label="Trust Anchor Config"
					issuer="edufed.gov"
					subject="edufed.gov"
					keyLabel="K_ta (self)"
					verified
				/>
				<p className="text-sm font-semibold text-emerald-600 text-center mt-2">
					Chain fully verified — trust established!
				</p>
			</div>
		),
	},
];

const verificationSteps = [
	{
		title: "1. Start at Trust Anchor",
		content: (
			<p className="text-sm">
				Pre-configured K_ta is already trusted. Verify link [3] (TA Entity Config) is self-signed
				with K_ta.
			</p>
		),
	},
	{
		title: "2. Verify [2] using K_ta",
		content: (
			<p className="text-sm">
				K_ta verifies the signature on [2] (TA → Intermediate Subordinate Statement). The JWKS in
				[2] reveals K_intermediate.
			</p>
		),
	},
	{
		title: "3. Verify [1] using K_intermediate",
		content: (
			<p className="text-sm">
				K_intermediate verifies [1] (Intermediate → Leaf Subordinate Statement). The JWKS in [1]
				reveals K_leaf.
			</p>
		),
	},
	{
		title: "4. Verify [0] using K_leaf",
		content: (
			<p className="text-sm">
				K_leaf verifies [0] (Leaf Entity Configuration). The chain is cryptographically complete.
			</p>
		),
	},
	{
		title: "5. Final checks",
		content: (
			<div className="text-sm space-y-1">
				<p>
					Check <code>exp</code> and <code>iat</code> on every link — reject expired statements.
				</p>
				<p>
					Verify issuer/subject chaining: <code>ES[j].iss == ES[j+1].sub</code>.
				</p>
				<p>
					Enforce <code>max_path_length</code> constraints (Section 6.2).
				</p>
				<p>Apply metadata policies from each Subordinate Statement.</p>
			</div>
		),
	},
];

export default function Lesson04() {
	return (
		<LessonPage
			lesson={getLesson(4)}
			minutes={8}
			lastReviewed={handle.lastUpdated}
			furtherReading={{
				specSections: [
					{ sec: "4", title: "Trust Chain" },
					{ sec: "4.1", title: "Beginning and Ending Trust Chains" },
					{ sec: "4.2", title: "Trust Chain Example" },
					{ sec: "10.2", title: "Validating a Trust Chain" },
					{ sec: "3.2", title: "Entity Statement Validation" },
				],
				rfcs: [{ num: 7515, title: "JSON Web Signature (JWS)" }],
			}}
		>
			<h2 id="build-a-trust-chain">Build a Trust Chain — Step by Step</h2>
			<p>
				A Trust Chain is an ordered sequence of Entity Statements, starting with the subject's
				Entity Configuration and ending at a Trust Anchor's Entity Configuration (
				<SpecRef sec="4.1" title="Beginning and Ending Trust Chains" />
				). Each intermediate link is a Subordinate Statement that cryptographically vouches for the
				entity below it.
			</p>
			<StepThrough steps={buildSteps} />

			<h2 id="how-verification-works">How Verification Works</h2>
			<p>
				Verification proceeds <strong>top-down</strong> — start from the Trust Anchor whose key you
				already trust, and work your way down to the leaf (
				<SpecRef sec="10.2" title="Validating a Trust Chain" />
				).
			</p>
			<StepThrough steps={verificationSteps} />

			<Callout variant="security" sec="3.2" secTitle="Entity Statement Validation">
				Every Entity Statement MUST use the <code>typ</code> JWS header parameter with the value{" "}
				<code>entity-statement+jwt</code>. Statements with a missing or unrecognized <code>typ</code>{" "}
				MUST be rejected — this prevents cross-JWT confusion attacks per{" "}
				<SpecRef sec="3.2" /> and RFC&nbsp;8725 §3.11.
			</Callout>

			<AnalogyBox>
				Imagine applying for a job abroad. Your resume (Entity Config) is backed by your professor's
				recommendation letter (Subordinate Statement), which is backed by the university president's
				confirmation (another Subordinate Statement), which terminates at the university's own
				identity document (TA Config). Each letter is signed by a different person, and the employer
				verifies them in order from the top.
			</AnalogyBox>
		</LessonPage>
	);
}
