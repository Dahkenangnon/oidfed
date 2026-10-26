import { isLanguageTag, JWKSetSchema } from "@oidfed/core";
import { z } from "zod";

const strings = z.array(z.string()).min(1);
const object = z.record(z.string(), z.unknown());
const identifier = z.string().regex(/^[A-Za-z0-9_-]+$/);
const https = z.url().refine((value) => new URL(value).protocol === "https:", "Must use HTTPS");
const issuerId = https.refine(
	(value) => !value.includes("?") && !value.includes("#"),
	"Issuer must not contain query or fragment components",
);
const path = z.array(z.union([z.string(), z.null(), z.number().int().nonnegative()])).min(1);
const algorithm = z.union([z.string(), z.number().int()]);

const claimQuery = z.looseObject({
	id: identifier.optional(),
	path,
	values: z
		.array(z.union([z.string(), z.number().int(), z.boolean()]))
		.min(1)
		.optional(),
});

const credentialQuery = z
	.looseObject({
		id: identifier,
		format: z.string(),
		meta: object,
		multiple: z.boolean().optional(),
		trusted_authorities: z
			.array(z.looseObject({ type: z.string(), values: strings }))
			.min(1)
			.optional(),
		require_cryptographic_holder_binding: z.boolean().optional(),
		claims: z.array(claimQuery).min(1).optional(),
		claim_sets: z.array(z.array(identifier)).min(1).optional(),
	})
	.superRefine((query, ctx) => {
		const fail = (message: string) => ctx.addIssue({ code: "custom", message });
		const ids = query.claims?.flatMap((claim) => (claim.id === undefined ? [] : [claim.id])) ?? [];
		if (new Set(ids).size !== ids.length) fail("Claim identifiers must be unique");
		const claimPaths = query.claims?.map((claim) => JSON.stringify(claim.path)) ?? [];
		if (new Set(claimPaths).size !== claimPaths.length)
			fail("Claim queries must not repeat a path");
		if (
			query.claim_sets &&
			(!query.claims ||
				query.claims.some((claim) => claim.id === undefined) ||
				query.claim_sets.some((set) => set.some((id) => !ids.includes(id))))
		)
			fail("Claim sets must reference named claims");
		if (query.format === "mso_mdoc") {
			if (typeof query.meta.doctype_value !== "string") fail("mdoc queries require doctype_value");
			if (
				query.claims?.some(
					(claim) => claim.path.length !== 2 || claim.path.some((part) => typeof part !== "string"),
				)
			)
				fail("mdoc claim paths must contain two strings");
		}
		if (query.format === "dc+sd-jwt" && !strings.safeParse(query.meta.vct_values).success)
			fail("SD-JWT queries require vct_values");
		if (
			["jwt_vc_json", "jwt_vc_json-ld", "ldp_vc"].includes(query.format) &&
			!z.array(strings).min(1).safeParse(query.meta.type_values).success
		)
			fail("W3C queries require type_values");
	});

export const DcqlQuerySchema = z
	.looseObject({
		credentials: z.array(credentialQuery).min(1),
		credential_sets: z
			.array(z.looseObject({ options: z.array(strings).min(1), required: z.boolean().optional() }))
			.min(1)
			.optional(),
	})
	.superRefine((query, ctx) => {
		const ids = query.credentials.map((credential) => credential.id);
		if (new Set(ids).size !== ids.length)
			ctx.addIssue({ code: "custom", message: "Credential identifiers must be unique" });
		if (
			query.credential_sets?.some((set) =>
				set.options.some((option) => option.some((id) => !ids.includes(id))),
			)
		)
			ctx.addIssue({
				code: "custom",
				message: "Credential sets must reference defined credentials",
			});
	});
export type DcqlQuery = z.infer<typeof DcqlQuerySchema>;

const formatCapabilities = z.record(
	z.string(),
	z.looseObject({
		alg_values: strings.optional(),
		proof_type_values: strings.optional(),
		cryptosuite_values: strings.optional(),
		issuerauth_alg_values: z.array(algorithm).min(1).optional(),
		deviceauth_alg_values: z.array(algorithm).min(1).optional(),
		"sd-jwt_alg_values": strings.optional(),
		"kb-jwt_alg_values": strings.optional(),
	}),
);

const keyReferences = {
	jwks: JWKSetSchema.optional(),
	jwks_uri: https.optional(),
	signed_jwks_uri: https.optional(),
};

export const WalletProviderMetadataSchema = z.looseObject({
	vp_formats_supported: formatCapabilities,
	client_id_prefixes_supported: strings.optional(),
	// Protocol-key representations are an integration convention, not new Wallet fields.
	...keyReferences,
});
export type WalletProviderMetadata = z.infer<typeof WalletProviderMetadataSchema>;

export const CredentialVerifierMetadataSchema = z.looseObject({
	vp_formats_supported: formatCapabilities,
	...keyReferences,
	request_uris: z.array(https).min(1).optional(),
	response_uris: z.array(https).min(1).optional(),
	redirect_uris: z.array(https).min(1).optional(),
	dcql_queries: z.array(DcqlQuerySchema).min(1).optional(),
});
export type CredentialVerifierMetadata = z.infer<typeof CredentialVerifierMetadataSchema>;

const logo = z.looseObject({ uri: z.url(), alt_text: z.string().optional() });
const display = z.looseObject({
	name: z.string().optional(),
	locale: z.string().optional(),
	logo: logo.optional(),
});
function validateDisplayLocales(
	values: readonly { locale?: string | undefined }[],
	ctx: z.RefinementCtx,
): void {
	const locales = values.flatMap((value) =>
		value.locale === undefined ? [] : [value.locale.toLowerCase()],
	);
	if (new Set(locales).size !== locales.length)
		ctx.addIssue({ code: "custom", message: "Display locales must be unique" });
	if (locales.some((locale) => !isLanguageTag(locale)))
		ctx.addIssue({ code: "custom", message: "Invalid display locale" });
}
const displays = z.array(display).min(1).superRefine(validateDisplayLocales);
const claimDisplays = z
	.array(z.looseObject({ name: z.string().optional(), locale: z.string().optional() }))
	.min(1)
	.superRefine(validateDisplayLocales);
interface ClaimPathNode {
	children: Map<string | number | null, ClaimPathNode>;
	kind?: "object" | "array";
	wildcard?: boolean;
	indexed?: boolean;
	terminal?: boolean;
}
const claimDescriptions = z
	.array(
		z.looseObject({
			path: z.array(z.union([z.string(), z.null(), z.number().int()])).min(1),
			mandatory: z.boolean().optional(),
			display: claimDisplays.optional(),
		}),
	)
	.min(1);
function validateClaimDescriptions(
	claims: readonly z.infer<typeof claimDescriptions>[number][],
	ctx: z.RefinementCtx,
	mdoc: boolean,
): void {
	const root: ClaimPathNode = { children: new Map() };
	for (const claim of claims) {
		if (
			mdoc
				? claim.path.length < 2 ||
					typeof claim.path[0] !== "string" ||
					typeof claim.path[1] !== "string"
				: claim.path.some((component) => typeof component === "number" && component < 0)
		) {
			ctx.addIssue({
				code: "custom",
				message: "Invalid claim description path for the credential format",
			});
			return;
		}
		let node = root;
		for (const component of claim.path) {
			// VCI Appendix C.2 allows integer CBOR map keys; a nonnegative integer is ambiguous.
			const kind =
				typeof component === "string" || (mdoc && typeof component === "number" && component < 0)
					? "object"
					: component === null || !mdoc
						? "array"
						: undefined;
			const indexed = typeof component === "number" && component >= 0;
			if (
				(kind && node.kind && node.kind !== kind) ||
				(component === null && node.indexed) ||
				(indexed && node.wildcard)
			) {
				ctx.addIssue({ code: "custom", message: "Claim descriptions contain conflicting paths" });
				return;
			}
			if (kind) node.kind = kind;
			if (component === null) node.wildcard = true;
			if (indexed) node.indexed = true;
			let next = node.children.get(component);
			if (!next) {
				next = { children: new Map() };
				node.children.set(component, next);
			}
			node = next;
		}
		if (node.terminal) {
			ctx.addIssue({ code: "custom", message: "Claim descriptions repeat the same path" });
			return;
		}
		node.terminal = true;
	}
}
const credentialDisplay = z
	.array(
		display.extend({
			name: z.string(),
			description: z.string().optional(),
			background_color: z.string().optional(),
			text_color: z.string().optional(),
			background_image: z.looseObject({ uri: z.url() }).optional(),
		}),
	)
	.min(1)
	.superRefine(validateDisplayLocales);
const proofMetadata = z.looseObject({
	proof_signing_alg_values_supported: z.array(algorithm).min(1),
	key_attestations_required: z
		.looseObject({ key_storage: strings.optional(), user_authentication: strings.optional() })
		.optional(),
});
const credentialConfiguration = z
	.looseObject({
		format: z.string(),
		scope: z.string().optional(),
		credential_signing_alg_values_supported: z.array(algorithm).min(1).optional(),
		cryptographic_binding_methods_supported: strings.optional(),
		proof_types_supported: z.record(z.string(), proofMetadata).optional(),
		credential_metadata: z
			.looseObject({
				display: credentialDisplay.optional(),
				claims: claimDescriptions.optional(),
			})
			.optional(),
	})
	.superRefine((configuration, ctx) => {
		const fail = (message: string) => ctx.addIssue({ code: "custom", message });
		validateClaimDescriptions(
			configuration.credential_metadata?.claims ?? [],
			ctx,
			configuration.format === "mso_mdoc",
		);
		if (
			(configuration.cryptographic_binding_methods_supported !== undefined) !==
			(configuration.proof_types_supported !== undefined)
		)
			fail("Binding methods and proof types must be provided together");
		if (configuration.format === "mso_mdoc" && typeof configuration.doctype !== "string")
			fail("mdoc configuration requires doctype");
		if (configuration.format === "dc+sd-jwt" && typeof configuration.vct !== "string")
			fail("SD-JWT configuration requires vct");
		if (["jwt_vc_json", "jwt_vc_json-ld", "ldp_vc"].includes(configuration.format)) {
			const definition = z
				.looseObject({ type: z.array(z.string()), "@context": z.array(z.unknown()).optional() })
				.safeParse(configuration.credential_definition);
			if (
				!definition.success ||
				(configuration.format !== "jwt_vc_json" && !definition.data["@context"])
			)
				fail("W3C configuration requires credential_definition with type and applicable @context");
		}
	});

export const CredentialIssuerMetadataSchema = z.looseObject({
	credential_issuer: issuerId,
	authorization_servers: z.array(issuerId).min(1).optional(),
	credential_endpoint: https,
	nonce_endpoint: https.optional(),
	deferred_credential_endpoint: https.optional(),
	notification_endpoint: https.optional(),
	credential_request_encryption: z
		.looseObject({
			jwks: JWKSetSchema,
			enc_values_supported: strings,
			encryption_required: z.boolean(),
			zip_values_supported: strings.optional(),
		})
		.optional(),
	credential_response_encryption: z
		.looseObject({
			alg_values_supported: strings,
			enc_values_supported: strings,
			encryption_required: z.boolean(),
			zip_values_supported: strings.optional(),
		})
		.optional(),
	batch_credential_issuance: z.looseObject({ batch_size: z.number().int().min(2) }).optional(),
	display: displays.optional(),
	credential_configurations_supported: z.record(z.string(), credentialConfiguration),
	...keyReferences,
});
export type CredentialIssuerMetadata = z.infer<typeof CredentialIssuerMetadataSchema>;

export const roleSchemas = {
	openid_wallet_provider: WalletProviderMetadataSchema,
	openid_credential_issuer: CredentialIssuerMetadataSchema,
	openid_credential_verifier: CredentialVerifierMetadataSchema,
} as const;
export type WalletRoleType = keyof typeof roleSchemas;
