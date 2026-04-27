import {
	Badge,
	Card,
	CardDescription,
	CardHeader,
	CardPanel,
	CardTitle,
	Tabs,
	TabsList,
	TabsPanel,
	TabsTab,
} from "@oidfed/ui";
import { Callout } from "~/components/callout";
import { CodeBlock } from "~/components/code-block";
import { LessonPage } from "~/components/lesson-page";
import { getLesson } from "~/data/lessons";

import { lessonMetaForSlug } from "~/lib/seo";
export const handle = { lastUpdated: "2026-04-28" };

export function meta() {
	return lessonMetaForSlug("real-use-cases");
}

const useCases = [
	{
		id: "healthcare",
		title: "Healthcare",
		emoji: "🏥",
		problem:
			"200+ hospitals, 12 networks, 50 insurers, hundreds of pharmacies — 40,000+ bilateral configurations needed.",
		topology:
			"National Health Authority (TA) → Regional Networks + Insurance Association (IA) → Hospitals, Insurers, Pharmacies (Leaf)",
		trustMarks: ["HIPAA Compliant", "Emergency Access Certified"],
		policyExample:
			'encryption_required: { value: true }\nsupported_encryption_algs: { subset_of: ["A256GCM", "A128CBC-HS256"] }\naudit_logging: { essential: true }',
		takeaway:
			"Federation eliminates tens of thousands of bilateral agreements while ensuring every participant meets healthcare security standards.",
	},
	{
		id: "banking",
		title: "Open Banking",
		emoji: "🏦",
		problem:
			"PSD2 requires verified data sharing between banks and fintechs. Regulators need visibility into who's authorized.",
		topology:
			"Central Bank/Regulator (TA) → Banking Association + Fintech Alliance (IA) → Banks (AS) + Fintech Apps (OAuth Client)",
		trustMarks: ["PSD2 AISP Licensed", "PSD2 PISP Licensed", "Strong Customer Auth Compliant"],
		policyExample:
			'token_endpoint_auth_method: { one_of: ["private_key_jwt", "tls_client_auth"] }\ngrant_types: { subset_of: ["authorization_code", "refresh_token"] }\nrequire_signed_request_object: { value: true }',
		takeaway:
			"Trust Marks prove regulatory compliance. Metadata policies enforce security baselines that fintechs cannot circumvent.",
	},
	{
		id: "government",
		title: "Government (eIDAS-Style)",
		emoji: "🏛️",
		problem:
			"Cross-border citizen identity — each nation is sovereign but citizens need to authenticate across borders.",
		topology:
			"Multi-anchor with bridge: France TA, Germany TA, Spain TA → EU Bridge Entity → National IdPs + Service Portals",
		trustMarks: ["eIDAS Low", "eIDAS Substantial", "eIDAS High", "GDPR Compliant Processor"],
		policyExample:
			'id_token_signing_alg_values_supported: { subset_of: ["ES256", "PS256"] }\nacr_values_supported: { superset_of: ["eidas-substantial"] }',
		takeaway:
			"Multi-anchor topology respects national sovereignty while enabling cross-border trust through bridge entities.",
	},
	{
		id: "research",
		title: "Research Consortium",
		emoji: "🔬",
		problem:
			"Multi-university consortium sharing datasets, compute resources, and collaboration tools across institutional boundaries.",
		topology:
			"Research Council (TA) → STEM Alliance + Social Science Network (IA) → University Login (OP), Data Platform (RS), HPC Cluster (RS), Collab Tool (RP)",
		trustMarks: ["Data Stewardship Certified", "FAIR Data Compliant", "Secure Compute Environment"],
		policyExample:
			'scopes_supported: { superset_of: ["openid", "eduperson_entitlement"] }\ntoken_lifetime: { value: 3600 }',
		takeaway:
			"Federation connects diverse institutions and resource types under a single trust framework, with role-appropriate policies.",
	},
	{
		id: "iot",
		title: "IoT / Manufacturing",
		emoji: "🏭",
		problem:
			"Verifying legitimate IoT devices from multiple OEMs. No 'user login' — device-to-device trust.",
		topology:
			"Industry Consortium (TA) → OEM Manufacturers + System Integrator (IA) → Sensors, Actuators, Edge Gateways, Factory Platforms (Leaf)",
		trustMarks: ["IEC 62443 Level 2", "OEM Genuine Device", "Firmware Current (24h expiry)"],
		policyExample:
			'firmware_signing: { value: true }\ncommunication_protocols: { subset_of: ["MQTT-TLS", "CoAP-DTLS"] }\nmin_key_strength: { value: 256 }\nremote_attestation: { essential: true }',
		takeaway:
			"Federation extends beyond OIDC — custom metadata types (iot_device, iot_gateway) enable device-to-device trust without user authentication.",
	},
	{
		id: "telecom",
		title: "Telecom Roaming",
		emoji: "📡",
		problem:
			"Bilateral roaming agreements for mobile networks are complex to manage at scale across regions.",
		topology:
			"GSMA Europe + GSMA Asia-Pacific (TAs) → UK Ofcom, DE BNetzA, JP MIC (IA) → Mobile Operators (Leaf)",
		trustMarks: ["Licensed MNO", "GSMA Roaming Certified", "5G SA Ready"],
		policyExample:
			'roaming_protocols: { subset_of: ["DIAMETER", "HTTP/2"] }\ninterconnect_security: { value: "IPsec" }',
		takeaway:
			"Custom metadata types describe telecom capabilities. Multi-region TA topology handles jurisdictional differences.",
	},
	{
		id: "ai-agents",
		title: "AI Agents",
		emoji: "🤖",
		problem:
			"AI agents acting on behalf of users or organizations need verifiable identity — who built them, what they're authorized to do, and whether they can be trusted by other agents or services.",
		topology:
			"AI Governance Body (TA) → Platform Providers + Enterprise Deployers (IA) → AI Agents, Tool Services, Orchestrators (Leaf)",
		trustMarks: ["Safety Evaluated", "Data Handling Certified", "Human-in-the-Loop Verified"],
		policyExample:
			'max_autonomy_level: { one_of: ["supervised", "semi-autonomous", "autonomous"] }\nallowed_actions: { subset_of: ["read", "write", "execute", "delegate"] }\ndata_access_scope: { subset_of: ["public", "org-internal", "user-specific"] }\nmodel_transparency: { essential: true }',
		takeaway:
			"Federation provides a natural framework for agent-to-agent trust — verifiable identity chains mean an AI agent can prove its provenance, capabilities, and compliance without a central registry.",
	},
	{
		id: "wallets",
		title: "Digital Wallets (EUDI)",
		emoji: "👛",
		problem:
			"The EU Digital Identity Wallet ecosystem requires trust between Wallet Providers, Credential Issuers, and Verifiers across member states.",
		topology:
			"EU Commission (TA) → National eID Authorities (IA) → Wallet Providers, Credential Issuers, Relying Parties (Leaf)",
		trustMarks: ["EUDI Wallet Certified", "LoA High Issuer", "Qualified Trust Service"],
		policyExample:
			'wallet_protocol_versions: { subset_of: ["OID4VP-1.0", "OID4VCI-1.0"] }\ncredential_formats: { superset_of: ["sd-jwt-vc"] }\nkey_storage: { one_of: ["secure_element", "cloud_hsm"] }\nloa_min: { value: "high" }',
		takeaway:
			"OpenID Federation is already being adopted for EUDI Wallet trust establishment — see the OpenID Federation Wallet Architectures specification for the formal framework.",
	},
];

export default function Lesson14() {
	return (
		<LessonPage
			lesson={getLesson(14)}
			minutes={16}
			lastReviewed={handle.lastUpdated}
			furtherReading={{
				specSections: [
					{ sec: "5", title: "Metadata" },
					{ sec: "17", title: "Implementation Considerations" },
				],
				external: [
					{
						title: "A Trusted Foundation for the EUDI Wallet in Research and Education",
						source: "Paul den Hertog, Niels van Dijk, Klaas Wierenga · GÉANT CONNECT",
						date: "Jul 2025",
						href: "https://connect.geant.org/2025/07/24/a-trusted-foundation-for-the-eudi-wallet-in-research-and-education-why-edugain-and-openid-federation-matter",
					},
					{
						title: "DC4EU final report — Pluralistic trust model for the EUDI Wallet",
						source: "GÉANT CONNECT",
						date: "Feb 2026",
						href: "https://connect.geant.org/2026/02/03/dc4eu-final-report-proposes-pluralistic-trust-model-to-realise-eudi-wallet-vision",
					},
					{
						title: "Selecting OpenID Federation for the DCC & Credential Engine Issuer Registry",
						source: "R.X. Schwartz · Digital Credentials Consortium",
						date: "Jan 2025",
						href: "https://blog.dcconsortium.org/selecting-the-openid-federation-specification-for-the-dcc-and-credential-engine-issuer-registry-f9079f620472",
					},
					{
						title: "The Journey to OpenID Federation 1.0 is Complete",
						source: "Mike Jones · self-issued.info",
						date: "Feb 2026",
						href: "https://self-issued.info/?p=2813",
					},
					{
						title: "Nine countries prove OpenID Federation interoperability",
						source: "OpenID Foundation",
						date: "Feb 2026",
						href: "https://openid.net/nine-countries-prove-openid-federation-interoperability/",
					},
					{
						title: "OpenID Federation Wallet Architectures 1.0 (draft)",
						source: "OpenID Foundation",
						href: "https://openid.net/specs/openid-federation-wallet-1_0.html",
					},
				],
			}}
		>
			<p>
				Federation isn't just for login — it's not even just for OpenID Connect. Diverse industries
				use OpenID Federation's protocol-independent trust framework to solve real problems, from
				healthcare data sharing to AI agent identity verification.
			</p>

			<Card className="my-6">
				<CardPanel className="space-y-3">
					<h3 className="text-base font-semibold">Beyond OpenID Connect</h3>
					<p className="text-sm text-muted-foreground">
						The specification was originally drafted as <em>OpenID Connect Federation 1.0</em>{" "}
						and renamed to <em>OpenID Federation 1.0</em> once it was clear the underlying trust
						framework — Entity Statements, Trust Chains, Trust Marks, Metadata Policies — is
						independent of OpenID Connect and applies to any protocol. Michael&nbsp;B.&nbsp;Jones,
						a spec co-author, recounts the project's arc in his retrospective{" "}
						<a
							href="https://self-issued.info/?p=2813"
							target="_blank"
							rel="noopener noreferrer"
							className="underline underline-offset-2 hover:text-foreground"
						>
							"The Journey to OpenID Federation 1.0 is Complete"
						</a>
						.
					</p>
					<p className="text-sm text-muted-foreground">
						This insight motivates the planned 1.1 split into two drafts:{" "}
						<strong>OpenID Federation 1.1</strong> (the protocol-independent trust layer) and{" "}
						<strong>OpenID Federation for OpenID Connect 1.1</strong> (OIDC/OAuth-specific
						bindings). Federation can be applied anywhere trust establishment via hierarchy is
						needed on the internet.
					</p>
				</CardPanel>
			</Card>

			<Callout variant="note" title="These examples are illustrative">
				The use cases below are <strong>illustrative abstractions</strong> showing how OpenID
				Federation's mechanisms could be applied in various industries. The metadata fields, policy
				operators, and trust-mark names shown are <strong>not defined by the official
				specification</strong> — they demonstrate how the spec's extensible framework can be
				profiled to a sector. Do not assume any of the field names are wire-compatible across
				deployments without checking the relevant sector profile.
			</Callout>

			<Tabs defaultValue="healthcare">
				<TabsList className="flex-wrap">
					{useCases.map((uc) => (
						<TabsTab key={uc.id} value={uc.id}>
							{uc.emoji} {uc.title}
						</TabsTab>
					))}
				</TabsList>
				{useCases.map((uc) => (
					<TabsPanel key={uc.id} value={uc.id} className="mt-4">
						<Card>
							<CardHeader>
								<CardTitle>
									{uc.emoji} {uc.title}
								</CardTitle>
								<CardDescription>{uc.problem}</CardDescription>
							</CardHeader>
							<CardPanel className="space-y-4">
								<div>
									<h4 className="text-sm font-semibold mb-1">Topology</h4>
									<p className="text-sm text-muted-foreground">{uc.topology}</p>
								</div>
								<div>
									<h4 className="text-sm font-semibold mb-1">Trust Marks</h4>
									<div className="flex flex-wrap gap-1">
										{uc.trustMarks.map((tm) => (
											<Badge key={tm} variant="outline" size="sm">
												{tm}
											</Badge>
										))}
									</div>
								</div>
								<div>
									<h4 className="text-sm font-semibold mb-1">Illustrative Policy Example</h4>
									<CodeBlock lang="json" filename={`${uc.id}-policy.json (illustrative)`}>
										{uc.policyExample}
									</CodeBlock>
								</div>
								<div className="rounded bg-brand-50 dark:bg-brand-950/20 p-3 text-sm">
									<strong>Key Takeaway:</strong> {uc.takeaway}
								</div>
							</CardPanel>
						</Card>
					</TabsPanel>
				))}
			</Tabs>

		</LessonPage>
	);
}
