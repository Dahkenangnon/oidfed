import {
	Alert,
	AlertDescription,
	AlertTitle,
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
import { Info } from "lucide-react";
import { SourcesSection } from "~/components/footnote";
import { LessonPage } from "~/components/lesson-page";
import { getLesson } from "~/data/lessons";

export const handle = { lastUpdated: "2026-04-20" };

export function meta() {
	return [
		{ title: "Real-World Use Cases — Learn OpenID Federation" },
		{
			name: "description",
			content:
				"How diverse industries use OpenID Federation to solve real trust problems — healthcare, banking, government, research, IoT, telecom, AI agents, and digital wallets.",
		},
		{ name: "author", content: "Justin Dah-kenangnon" },
		{ property: "og:title", content: "Real-World Use Cases" },
		{
			property: "og:description",
			content: "Eight industry scenarios showing federation in action.",
		},
		{ property: "og:type", content: "article" },
		{ property: "article:author", content: "https://dahkenangnon.com" },
		{ property: "article:section", content: "Going Deeper" },
	];
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
		<LessonPage lesson={getLesson(14)}>
			<p>
				Federation isn't just for login — it's not even just for OpenID Connect. Diverse industries
				use OpenID Federation's protocol-independent trust framework to solve real problems, from
				healthcare data sharing to AI agent identity verification.
			</p>

			<Card className="my-6">
				<CardPanel className="space-y-3">
					<h3 className="text-base font-semibold">Beyond OpenID Connect</h3>
					<p className="text-sm text-muted-foreground">
						The specification was originally called "OpenID Connect Federation 1.0" but was renamed
						to "OpenID Federation 1.0" once its authors realized the trust framework is
						protocol-independent. As Michael B. Jones explained:
					</p>
					<blockquote className="border-l-4 border-brand-300 dark:border-brand-700 pl-4 text-sm italic text-muted-foreground">
						"We renamed it because we realized that while we'd built it for OpenID Connect, the
						federation mechanisms — Entity Statements, Trust Chains, Trust Marks, Metadata Policies
						— are all protocol-independent. They can establish trust for any kind of entity on the
						internet."
					</blockquote>
					<p className="text-sm text-muted-foreground">
						This insight led to the upcoming 1.1 split into two specifications:{" "}
						<strong>OpenID Federation 1.1</strong> (the protocol-independent trust layer) and{" "}
						<strong>OpenID Federation for OpenID Connect 1.1</strong> (OIDC/OAuth-specific
						bindings). Federation can be applied anywhere trust establishment via hierarchy is
						needed on the internet.
					</p>
				</CardPanel>
			</Card>

			<Alert variant="info" className="my-6">
				<Info />
				<AlertTitle>These examples are illustrative</AlertTitle>
				<AlertDescription>
					The use cases below are illustrative abstractions showing how OpenID Federation's
					mechanisms could be applied in various industries. The metadata fields, policy operators,
					and trust mark names shown are not defined by the official specification — they
					demonstrate how the spec's extensible framework works in practice.
				</AlertDescription>
			</Alert>

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
									<h4 className="text-sm font-semibold mb-1">Policy Example</h4>
									<pre className="rounded bg-muted p-3 text-xs overflow-x-auto">
										{uc.policyExample}
									</pre>
								</div>
								<div className="rounded bg-brand-50 dark:bg-brand-950/20 p-3 text-sm">
									<strong>Key Takeaway:</strong> {uc.takeaway}
								</div>
							</CardPanel>
						</Card>
					</TabsPanel>
				))}
			</Tabs>

			<SourcesSection
				sources={[
					{
						id: "1",
						text: "OpenID Federation 1.0 — Full Specification",
						url: "https://openid.net/specs/openid-federation-1_0.html",
					},
					{
						id: "2",
						text: "eIDAS Regulation (EU) — Electronic Identification",
						url: "https://digital-strategy.ec.europa.eu/en/policies/eidas-regulation",
					},
					{
						id: "3",
						text: "PSD2 Directive — Payment Services",
						url: "https://ec.europa.eu/info/law/payment-services-psd-2-directive-eu-2015-2366_en",
					},
					{
						id: "4",
						text: "Michael B. Jones — Renaming OpenID Connect Federation",
						url: "https://self-issued.info/?p=2813",
					},
					{
						id: "5",
						text: "OpenID Federation 1.1 (Draft)",
						url: "https://openid.net/specs/openid-federation-1_1.html",
					},
					{
						id: "6",
						text: "OpenID Federation for OpenID Connect 1.1 (Draft)",
						url: "https://openid.net/specs/openid-federation-connect-1_1.html",
					},
					{
						id: "7",
						text: "OpenID Federation Wallet Architectures 1.0",
						url: "https://openid.net/specs/openid-federation-wallet-1_0.html",
					},
				]}
			/>
		</LessonPage>
	);
}
