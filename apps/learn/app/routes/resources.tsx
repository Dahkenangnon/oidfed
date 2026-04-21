import {
	Badge,
	Button,
	Table,
	TableBody,
	TableCell,
	TableHead,
	TableHeader,
	TableRow,
	Tabs,
	TabsContent,
	TabsList,
	TabsTrigger,
} from "@oidfed/ui";
import { BookOpen, ExternalLink } from "lucide-react";
import { Link } from "react-router";
import { ThemeToggle } from "~/components/theme-toggle";

export const handle = { lastUpdated: "2026-04-20" };

export function meta() {
	return [
		{ title: "Resources — Learn OpenID Federation" },
		{
			name: "description",
			content:
				"Official specifications, RFCs, implementations, key people, and community resources for OpenID Federation.",
		},
		{ name: "author", content: "Justin Dah-kenangnon" },
		{ property: "og:title", content: "OpenID Federation Resources" },
		{
			property: "og:description",
			content: "Specifications, RFCs, implementations, people, and community links.",
		},
		{ property: "og:type", content: "website" },
		{ property: "article:author", content: "https://dahkenangnon.com" },
	];
}

interface Spec {
	title: string;
	url: string;
	description: string;
	status?: string;
	statusVariant?: "default" | "success" | "warning" | "info";
	category: "final" | "draft" | "rfc";
}

interface Implementation {
	title: string;
	url: string;
	description: string;
	status: string;
	statusVariant: "default" | "success" | "warning" | "info";
	category: "implementation" | "community";
}

interface Person {
	name: string;
	url: string;
	role: string;
	affiliation: string;
	description: string;
	tier: "core" | "adjacent";
}

const specs: Spec[] = [
	{
		title: "OpenID Federation 1.0",
		url: "https://openid.net/specs/openid-federation-1_0.html",
		description: "The core specification for multilateral federation.",
		status: "Final",
		statusVariant: "success",
		category: "final",
	},
	{
		title: "OpenID Federation 1.1",
		url: "https://openid.net/specs/openid-federation-1_1.html",
		description:
			"Protocol-independent successor — Entity Statements, Trust Chains, Metadata, Policies, Trust Marks, Federation Endpoints.",
		status: "Draft",
		statusVariant: "warning",
		category: "draft",
	},
	{
		title: "OpenID Federation for OpenID Connect 1.1",
		url: "https://openid.net/specs/openid-federation-connect-1_1.html",
		description:
			"Protocol-specific successor — OAuth 2.0 / OpenID Connect entity types, client registration flows.",
		status: "Draft",
		statusVariant: "warning",
		category: "draft",
	},
	{
		title: "OpenID Federation Wallet Architectures",
		url: "https://openid.net/specs/openid-federation-wallet-1_0.html",
		description: "Trust establishment for Wallet ecosystems with OpenID Federation.",
		status: "Draft",
		statusVariant: "warning",
		category: "draft",
	},
	{
		title: "OpenID Federation Extended Listing",
		url: "https://openid.net/specs/openid-federation-extended-listing-1_0.html",
		description: "Subordinate Listings Specification for large-scale federations.",
		status: "Draft",
		statusVariant: "warning",
		category: "draft",
	},
	{
		title: "RFC 7515 — JSON Web Signature (JWS)",
		url: "https://www.rfc-editor.org/rfc/rfc7515",
		description: "Compact serialization used for all Entity Statements and Trust Marks.",
		category: "rfc",
	},
	{
		title: "RFC 7516 — JSON Web Encryption (JWE)",
		url: "https://www.rfc-editor.org/rfc/rfc7516",
		description:
			"Optional encryption serialization format used alongside JWS in the specification.",
		category: "rfc",
	},
	{
		title: "RFC 7517 — JSON Web Key (JWK)",
		url: "https://www.rfc-editor.org/rfc/rfc7517",
		description: "Key representation used in the jwks claim.",
		category: "rfc",
	},
	{
		title: "RFC 7519 — JSON Web Token (JWT)",
		url: "https://www.rfc-editor.org/rfc/rfc7519",
		description: "Base token format for Entity Statements and Trust Marks.",
		category: "rfc",
	},
	{
		title: "RFC 7591 — OAuth 2.0 Dynamic Client Registration Protocol",
		url: "https://www.rfc-editor.org/rfc/rfc7591",
		description:
			"Defines the client metadata vocabulary that federation client registration builds on.",
		category: "rfc",
	},
	{
		title: "RFC 7638 — JSON Web Key (JWK) Thumbprint",
		url: "https://www.rfc-editor.org/rfc/rfc7638",
		description: "Computes key thumbprints recommended for use as Key IDs in federation JWKS.",
		category: "rfc",
	},
	{
		title: "RFC 8414 — OAuth 2.0 Authorization Server Metadata",
		url: "https://www.rfc-editor.org/rfc/rfc8414",
		description:
			"Defines the authorization server metadata model that federation extends for the oauth_authorization_server entity type.",
		category: "rfc",
	},
	{
		title:
			"RFC 9101 — The OAuth 2.0 Authorization Framework: JWT-Secured Authorization Request (JAR)",
		url: "https://www.rfc-editor.org/rfc/rfc9101",
		description: "Request Objects used in automatic client registration.",
		category: "rfc",
	},
	{
		title: "RFC 9126 — OAuth 2.0 Pushed Authorization Requests",
		url: "https://www.rfc-editor.org/rfc/rfc9126",
		description:
			"Alternative delivery mechanism for signed Request Objects during automatic registration.",
		category: "rfc",
	},
	{
		title: "RFC 9728 — OAuth 2.0 Protected Resource Metadata",
		url: "https://www.rfc-editor.org/rfc/rfc9728",
		description:
			"Defines the protected resource metadata model that federation uses for the oauth_resource entity type.",
		category: "rfc",
	},
];

const implementations: Implementation[] = [
	{
		title: "@oidfed (TypeScript)",
		url: "https://github.com/Dahkenangnon/oidfed",
		description:
			"The complete OpenID Federation 1.0 implementation for JavaScript — runtime-agnostic, spec-compliant, built on Web API standards.",
		status: "Active",
		statusVariant: "success",
		category: "implementation",
	},
	{
		title: "Spid-CIE-OIDC (Python)",
		url: "https://github.com/italia/spid-cie-oidc-django",
		description: "Italian SPID/CIE OpenID Federation implementation in Django.",
		status: "Active",
		statusVariant: "success",
		category: "implementation",
	},
	{
		title: "Sphereon OpenID Federation (Kotlin)",
		url: "https://github.com/Sphereon-Opensource/OpenID-Federation",
		description:
			"Kotlin Multiplatform implementation with REST APIs — runs on JVM, JS, and Native.",
		status: "Active",
		statusVariant: "success",
		category: "implementation",
	},
	{
		title: "OpenID Federation TS (OpenWallet Foundation)",
		url: "https://github.com/openwallet-foundation-labs/openid-federation-ts",
		description: "TypeScript implementation from the EUDI Wallet Prototypes initiative.",
		status: "Active",
		statusVariant: "success",
		category: "implementation",
	},
	{
		title: "OpenID Foundation",
		url: "https://openid.net/",
		description: "The standards body behind OpenID Connect and OpenID Federation.",
		status: "Org",
		statusVariant: "info",
		category: "community",
	},
	{
		title: "OidFed Explorer",
		url: "https://explore.oidfed.com",
		description:
			"A visual tool for exploring live OpenID Federation deployments — inspect entity configurations, trace trust chains, and validate topology.",
		status: "Tool",
		statusVariant: "info",
		category: "community",
	},
	{
		title: "Learn OpenID Federation",
		url: "/lessons/what-is-federation",
		description: "This interactive learning app — 15 lessons covering the full specification.",
		status: "Course",
		statusVariant: "info",
		category: "community",
	},
];

const people: Person[] = [
	{
		name: "Roland Hedberg",
		url: "https://github.com/rohe",
		role: "Original Inventor",
		affiliation: "Independent, Sweden",
		description:
			"He did the very hard thing \u2013 starting from a blank sheet of paper and on it creating a new, useful, and elegant invention.",
		tier: "core",
	},
	{
		name: "Michael B. Jones",
		url: "https://self-issued.info",
		role: "Editor, 1.1 Specs",
		affiliation: "Self-Issued Consulting",
		description:
			"Editor of the 1.1 split specs. OpenID Foundation board member, prolific identity standards author.",
		tier: "core",
	},
	{
		name: "Andreas Åkre Solberg",
		url: "https://github.com/andreassolberg",
		role: "Automatic Registration Inventor",
		affiliation: "Sikt (formerly UNINETT), Norway",
		description:
			"An early contributor and the inventor of Automatic Registration, which greatly simplifies deployments.",
		tier: "core",
	},
	{
		name: "John Bradley",
		url: "https://thread-safe.net",
		role: "Security & Deployment",
		affiliation: "Semperis (prev. Yubico)",
		description: "Brought his practical security and deployment insights to the work.",
		tier: "core",
	},
	{
		name: "Giuseppe De Marco",
		url: "https://github.com/peppelinux",
		role: "Production Deployment Pioneer",
		affiliation: "Italian Dept. Digital Transformation",
		description:
			"Spearheaded production deployment for multiple Italian national federations and the Italian EUDI Wallet, informing the specification with real-world experience \u2013 particularly with the use of Trust Marks.",
		tier: "core",
	},
	{
		name: "Vladimir Dzhuvinov",
		url: "https://connect2id.com",
		role: "Early Implementer",
		affiliation: "Connect2id, founder & CTO",
		description:
			"An early implementer and brought his rigorous thinking about metadata operators and establishing trust to the effort.",
		tier: "core",
	},
	{
		name: "Aaron Parecki",
		url: "https://aaronparecki.com",
		role: "OAuth/OIDC Standards",
		affiliation: "Okta, Dir. of Identity Standards",
		description:
			"Director of Identity Standards at Okta. Maintains oauth.net, OIDF board member and IPSIE WG co-chair.",
		tier: "adjacent",
	},
];

function ExtLink({ href, children }: { href: string; children: React.ReactNode }) {
	const isInternal = href.startsWith("/");
	return (
		<a
			href={href}
			target={isInternal ? undefined : "_blank"}
			rel={isInternal ? undefined : "noopener noreferrer"}
			className="text-primary hover:underline inline-flex items-center gap-1"
		>
			{children}
			{!isInternal && <ExternalLink className="size-3 shrink-0" />}
		</a>
	);
}

const categoryLabels: Record<string, string> = {
	final: "Official Specifications",
	draft: "In-Progress Specifications & Extensions",
	rfc: "Related RFCs",
};

const implCategoryLabels: Record<string, string> = {
	implementation: "Implementations",
	community: "Community & Learning",
};

export default function Resources() {
	return (
		<div className="h-screen flex flex-col overflow-hidden">
			<header className="shrink-0 z-50 border-b border-border bg-background/80 backdrop-blur">
				<div className="max-w-5xl mx-auto flex items-center justify-between h-14 px-4">
					<Link to="/" className="flex items-center gap-2 font-semibold text-sm">
						<BookOpen className="size-4 text-primary" />
						Learn OpenID Federation
					</Link>
					<div className="flex items-center gap-2">
						<Button variant="ghost" size="sm" render={<Link to="/lessons/what-is-federation" />}>
							Lessons
						</Button>
						<ThemeToggle />
					</div>
				</div>
			</header>

			<div className="flex-1 overflow-y-auto">
				<main className="max-w-5xl mx-auto px-4 py-12 w-full">
					<h1 className="text-3xl font-bold tracking-tight mb-2">Resources</h1>
					<p className="text-muted-foreground mb-8">
						Specifications, implementations, key people, and community links for OpenID Federation.
					</p>

					<Tabs defaultValue="specs">
						<TabsList>
							<TabsTrigger value="specs">Specifications & RFCs</TabsTrigger>
							<TabsTrigger value="implementations">Implementations & Community</TabsTrigger>
							<TabsTrigger value="people">People to Follow</TabsTrigger>
						</TabsList>

						<TabsContent value="specs" className="mt-6">
							{(["final", "draft", "rfc"] as const).map((cat) => {
								const items = specs.filter((s) => s.category === cat);
								return (
									<div key={cat} className="mb-8">
										<h2 className="text-lg font-semibold mb-3">{categoryLabels[cat]}</h2>
										<Table>
											<TableHeader>
												<TableRow>
													<TableHead>Title</TableHead>
													<TableHead className="hidden sm:table-cell">Description</TableHead>
													{cat !== "rfc" && <TableHead className="w-20">Status</TableHead>}
												</TableRow>
											</TableHeader>
											<TableBody>
												{items.map((item) => (
													<TableRow key={item.url}>
														<TableCell className="font-medium whitespace-normal">
															<ExtLink href={item.url}>{item.title}</ExtLink>
														</TableCell>
														<TableCell className="hidden sm:table-cell text-muted-foreground whitespace-normal">
															{item.description}
														</TableCell>
														{cat !== "rfc" && (
															<TableCell>
																<Badge variant={item.statusVariant ?? "secondary"} size="sm">
																	{item.status}
																</Badge>
															</TableCell>
														)}
													</TableRow>
												))}
											</TableBody>
										</Table>
									</div>
								);
							})}
						</TabsContent>

						<TabsContent value="implementations" className="mt-6">
							{(["implementation", "community"] as const).map((cat) => {
								const items = implementations.filter((i) => i.category === cat);
								return (
									<div key={cat} className="mb-8">
										<h2 className="text-lg font-semibold mb-3">{implCategoryLabels[cat]}</h2>
										<Table>
											<TableHeader>
												<TableRow>
													<TableHead>Title</TableHead>
													<TableHead className="hidden sm:table-cell">Description</TableHead>
													<TableHead className="w-20">Status</TableHead>
												</TableRow>
											</TableHeader>
											<TableBody>
												{items.map((item) => (
													<TableRow key={item.url}>
														<TableCell className="font-medium whitespace-normal">
															<ExtLink href={item.url}>{item.title}</ExtLink>
														</TableCell>
														<TableCell className="hidden sm:table-cell text-muted-foreground whitespace-normal">
															{item.description}
														</TableCell>
														<TableCell>
															<Badge variant={item.statusVariant} size="sm">
																{item.status}
															</Badge>
														</TableCell>
													</TableRow>
												))}
											</TableBody>
										</Table>
									</div>
								);
							})}
						</TabsContent>

						<TabsContent value="people" className="mt-6">
							{(["core", "adjacent"] as const).map((tier) => {
								const tierPeople = people.filter((p) => p.tier === tier);
								return (
									<div key={tier} className="mb-8">
										<h2 className="text-lg font-semibold mb-1">
											{tier === "core" ? "Core Specification Authors" : "Adjacent Ecosystem"}
										</h2>
										<p className="text-sm text-muted-foreground mb-3">
											{tier === "core"
												? "The six named authors of OpenID Federation 1.0 and its 1.1 successors, in order of editorial contribution."
												: "OIDF board members, OAuth/OIDC leaders shaping the broader protocol context."}
										</p>
										<Table>
											<TableHeader>
												<TableRow>
													<TableHead>Name</TableHead>
													<TableHead className="hidden md:table-cell">Affiliation</TableHead>
													<TableHead>Role</TableHead>
													<TableHead className="hidden sm:table-cell">
														Contribution{" "}
														<span className="font-normal text-xs italic">
															(verbatim from Jones' blog)
														</span>
													</TableHead>
												</TableRow>
											</TableHeader>
											<TableBody>
												{tierPeople.map((person) => (
													<TableRow key={person.name}>
														<TableCell className="font-medium whitespace-normal">
															<ExtLink href={person.url}>{person.name}</ExtLink>
														</TableCell>
														<TableCell className="hidden md:table-cell text-muted-foreground whitespace-normal">
															{person.affiliation}
														</TableCell>
														<TableCell>
															<Badge variant="info" size="sm">
																{person.role}
															</Badge>
														</TableCell>
														<TableCell className="hidden sm:table-cell text-muted-foreground whitespace-normal italic">
															"{person.description}"
														</TableCell>
													</TableRow>
												))}
											</TableBody>
										</Table>
									</div>
								);
							})}
							<p className="text-xs text-muted-foreground mt-4">
								Attribution source:{" "}
								<a
									href="https://self-issued.info/?p=2813"
									target="_blank"
									rel="noopener noreferrer"
									className="text-primary hover:underline"
								>
									The Journey to OpenID Federation 1.0 is Complete
								</a>{" "}
								— Michael B. Jones, February 2026.
							</p>
						</TabsContent>
					</Tabs>
				</main>

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
