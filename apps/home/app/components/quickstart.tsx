import { useState } from "react";
import { Link } from "react-router";
import { CopyButton, InstallCommand } from "./copy-button";
import { HighlightedCode } from "./highlighted-code";

/** One tab of the quickstart: a runnable example plus the links around it. */
interface QuickstartExample {
	/** Keys the server-highlighted markup and the tab/panel ARIA wiring. */
	readonly id: string;
	readonly label: string;
	readonly filename: string;
	readonly title: string;
	readonly description: string;
	readonly guide: string;
	readonly guideLabel: string;
	readonly install: string;
	readonly code: string;
	/** Shown only for examples that persist federation state. */
	readonly storageNote?: string;
}

export const quickstartExamples: readonly QuickstartExample[] = [
	{
		id: "anchor",
		label: "Trust Anchor",
		filename: "trust-anchor.ts",
		title: "Set up a Trust Anchor",
		description:
			"Publish a root of trust and serve signed Subordinate Statements for the participants you enroll.",
		guide: "/docs/features/1.1.entity-roles",
		guideLabel: "Set up a federation host",
		storageNote: "Use durable storage for a deployed authority.",
		install: "npm install @oidfed/authority @oidfed/core @oidfed/crypto",
		code: `import { TrustAnchor } from "@oidfed/authority";
import { MemoryFederationStorage, type CryptoContext } from "@oidfed/core";

export async function createAnchor(crypto: CryptoContext) {
  const entityId = "https://anchor.example";
  const anchor = await TrustAnchor.create({
    entityId,
    crypto,
    storage: new MemoryFederationStorage({ namespace: entityId }),
    metadata: {
      federation_entity: {
        federation_fetch_endpoint: \`\${entityId}/fetch\`,
        federation_list_endpoint: \`\${entityId}/list\`,
      },
    },
  });
  return anchor;
}`,
	},
	{
		id: "intermediate",
		label: "Intermediate",
		filename: "intermediate.ts",
		title: "Delegate trust to an Intermediate",
		description:
			"Point to an immediate superior and issue Subordinate Statements for the participants below you. Have the superior enroll your Intermediate.",
		guide: "/docs/features/1.3.subordinate-enrollment",
		guideLabel: "Enroll a subordinate",
		storageNote: "Use durable storage for a deployed authority.",
		install: "npm install @oidfed/authority @oidfed/core @oidfed/crypto",
		code: `import { Intermediate } from "@oidfed/authority";
import {
  MemoryFederationStorage, type CryptoContext, type TrustAnchorSet,
} from "@oidfed/core";

export async function createIntermediate(
  crypto: CryptoContext, trustAnchors: TrustAnchorSet,
) {
  const entityId = "https://authority.example";
  const intermediate = await Intermediate.create({
    entityId, crypto, trustAnchors,
    authorityHints: ["https://anchor.example"],
    storage: new MemoryFederationStorage({ namespace: entityId }),
    metadata: {
      federation_entity: {
        federation_fetch_endpoint: \`\${entityId}/fetch\`,
        federation_list_endpoint: \`\${entityId}/list\`,
      },
    },
  });
  return intermediate;
}`,
	},
	{
		id: "leaf",
		label: "Leaf",
		filename: "leaf.ts",
		title: "Publish a Leaf’s federation identity",
		description:
			"Publish a signed Entity Configuration that points to the authority that enrolled you. Add protocol roles as your application needs them.",
		guide: "/docs/api/leaf/hosts",
		guideLabel: "Read the Leaf API",
		install: "npm install @oidfed/leaf @oidfed/core @oidfed/crypto",
		code: `import { Leaf } from "@oidfed/leaf";
import type { CryptoContext, TrustAnchorSet } from "@oidfed/core";

export async function createLeaf(
  crypto: CryptoContext, trustAnchors: TrustAnchorSet,
) {
  const leaf = await Leaf.create({
    entityId: "https://participant.example",
    authorityHints: ["https://authority.example"],
    crypto,
    trustAnchors,
    metadata: {
      federation_entity: { organization_name: "Example participant" },
    },
  });
  return leaf;
}`,
	},
	{
		id: "roles",
		label: "Protocol roles",
		filename: "protocol-roles.ts",
		title: "Compose OIDC and wallet roles",
		description:
			"Use one Leaf as an OpenID Connect Relying Party and a Credential Verifier. Supply a protocol signer for Request Objects and wire in your OIDC and presentation engines.",
		guide: "/docs/features/1.1.entity-roles",
		guideLabel: "Compose protocol roles",
		install:
			"npm install @oidfed/leaf @oidfed/oidc @oidfed/wallet @oidfed/core @oidfed/crypto",
		code: `import { Leaf } from "@oidfed/leaf";
import { OidcRelyingPartyRole } from "@oidfed/oidc";
import { CredentialVerifierRole } from "@oidfed/wallet";
import type { CryptoContext, JWKSet, TrustAnchorSet } from "@oidfed/core";

export async function createParticipant(
  crypto: CryptoContext, trustAnchors: TrustAnchorSet,
  verifierKeys: JWKSet,
) {
  const participant = await Leaf.create({
    entityId: "https://portal.example",
    authorityHints: ["https://authority.example"],
    crypto, trustAnchors,
    metadata: { federation_entity: { organization_name: "Example portal" } },
    roles: [
      new OidcRelyingPartyRole({
        signing: { requestObject: "request_object" },
        metadata: {
          redirect_uris: ["https://portal.example/callback"],
          client_registration_types_supported: ["automatic"],
        },
      }),
      new CredentialVerifierRole({
        metadata: {
          jwks: verifierKeys,
          vp_formats_supported: {
            mso_mdoc: { issuerauth_alg_values: [-7], deviceauth_alg_values: [-7] },
          },
          response_uris: ["https://portal.example/presentation"],
        },
      }),
    ],
  });
  return participant;
}`,
	},
];

export function Quickstart({ highlighted }: { highlighted: Record<string, string> }) {
	const [active, setActive] = useState(0);

	return (
		<section
			id="quickstart"
			className="quickstart scroll-mt-8"
			aria-labelledby="quickstart-heading"
		>
			<div className="quickstart-header">
				<h2 id="quickstart-heading" className="site-section-title">
					Start with a federation participant
				</h2>
				<div
					role="tablist"
					aria-label="Quickstart examples"
					className="quickstart-tabs"
					onKeyDown={(event) => {
						const last = quickstartExamples.length - 1;
						let next: number;
						switch (event.key) {
							case "ArrowLeft":
								next = active === 0 ? last : active - 1;
								break;
							case "ArrowRight":
								next = active === last ? 0 : active + 1;
								break;
							case "Home":
								next = 0;
								break;
							case "End":
								next = last;
								break;
							default:
								return;
						}
						event.preventDefault();
						setActive(next);
						event.currentTarget.querySelectorAll("button")[next]?.focus();
					}}
				>
					{quickstartExamples.map(({ id, label }, index) => (
						<button
							key={id}
							type="button"
							id={`quickstart-tab-${id}`}
							role="tab"
							aria-controls={`quickstart-panel-${id}`}
							aria-selected={active === index}
							tabIndex={active === index ? 0 : -1}
							onClick={() => setActive(index)}
						>
							{label}
						</button>
					))}
				</div>
			</div>
			{quickstartExamples.map(
				({ id, title, description, install, filename, code, guide, guideLabel, storageNote }, index) => (
					<div
						key={id}
						id={`quickstart-panel-${id}`}
						aria-labelledby={`quickstart-tab-${id}`}
						role="tabpanel"
						hidden={active !== index}
						className="quickstart-panel"
					>
						<div className="min-w-0 p-5 sm:p-8">
							<h3 className="font-heading text-2xl font-semibold tracking-tight">{title}</h3>
							<p className="mt-3 max-w-[46ch] leading-relaxed text-muted-foreground">
								{description}
							</p>
							<div className="mt-5">
								<InstallCommand command={install} />
							</div>
							<p className="mt-4 max-w-[46ch] text-sm leading-relaxed text-muted-foreground">
								Bring your{" "}
								<Link className="site-link" to="/docs/api/crypto">
									crypto engine and keyring
								</Link>
								.{storageNote ? ` ${storageNote}` : ""}
							</p>
							<div className="mt-5 flex flex-wrap gap-x-5 gap-y-2 text-sm font-semibold">
								<Link className="site-link" to={guide}>
									{guideLabel}
								</Link>
								<Link className="site-link" to="/docs/features/11.5.http-wiring">
									Serve over HTTPS
								</Link>
							</div>
						</div>
						<div className="quickstart-code min-w-0">
							<div className="flex items-center justify-between gap-3 border-b border-border px-5 py-2.5 sm:px-7">
								<span className="font-mono text-xs text-muted-foreground">{filename}</span>
								<CopyButton text={code} label={`${filename} example`} />
							</div>
							<HighlightedCode
								html={highlighted[id] ?? ""}
								className="px-5 py-5 font-mono text-xs leading-relaxed sm:px-7 sm:text-[13px]"
							/>
						</div>
					</div>
				),
			)}
		</section>
	);
}
