import {
	isLanguageTag,
	isValidAlgorithm,
	isValidEntityId,
	JWKSetSchema,
	MetadataJWKSetSchema,
} from "@oidfed/core";
import { base64url } from "jose";
import { z } from "zod";

// These registered signing/MAC algorithms are unsuitable for JWE even when the
// current signing backend does not support them. Encryption extensions stay open.
const otherSignatureAlgorithms = new Set([
	"HS256",
	"HS384",
	"HS512",
	"RS384",
	"RS512",
	"ES256K",
	"EdDSA",
	"Ed25519",
	"Ed448",
	"ESP256",
	"ESP384",
	"ESP512",
]);
const strings = z.array(z.string()).min(1);
// RFC 6749 §3.3: a metadata scope is one token; an authorization scope is a token list.
const scopeToken = z.string().regex(/^[\x21\x23-\x5B\x5D-\x7E]+$/);
export const requestScopeSchema = z
	.string()
	.regex(/^[\x21\x23-\x5B\x5D-\x7E]+(?: [\x21\x23-\x5B\x5D-\x7E]+)*$/);
const nonblank = z
	.string()
	.refine((value) => value.trim().length > 0, "Identifier must not be blank");
const trustedAuthority = z
	.looseObject({ type: nonblank, values: strings })
	.superRefine((authority, ctx) => {
		for (const [index, value] of authority.values.entries()) {
			let valid = true;
			if (authority.type === "openid_federation") valid = isValidEntityId(value);
			if (authority.type === "aki") {
				try {
					valid = value.length > 0 && base64url.encode(base64url.decode(value)) === value;
				} catch {
					valid = false;
				}
			}
			if (!valid)
				ctx.addIssue({
					code: "custom",
					path: ["values", index],
					message: "Invalid trusted authority identifier",
				});
		}
	});
const object = z.record(z.string(), z.unknown());
const identifier = z.string().regex(/^[A-Za-z0-9_-]+$/);
const https = z.url().pipe(
	z
		.string()
		.refine((value) => new URL(value).protocol === "https:", "Must use HTTPS")
		.refine((value) => {
			const url = new URL(value);
			// URL parsing removes empty userinfo. Inspect the authority as well so
			// RFC 9110 §4.2.4's rejection policy also covers https://@host/.
			const authority = value.replace(/[\t\r\n]/g, "").match(/^[^:]*:[/\\]*([^/\\?#]*)/)?.[1];
			return !url.username && !url.password && !authority?.includes("@");
		}, "URL must not contain userinfo"),
);
const responseEndpoint = https.refine(
	(value) => !value.includes("#"),
	"Response endpoint must not contain a fragment",
);
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

const credentialQuery = (allowDuplicatePaths: boolean) =>
	z
		.looseObject({
			id: identifier,
			format: z.string(),
			meta: object,
			multiple: z.boolean().optional(),
			trusted_authorities: z.array(trustedAuthority).min(1).optional(),
			require_cryptographic_holder_binding: z.boolean().optional(),
			claims: z.array(claimQuery).min(1).optional(),
			claim_sets: z.array(z.array(identifier)).min(1).optional(),
		})
		.superRefine((query, ctx) => {
			const fail = (message: string) => ctx.addIssue({ code: "custom", message });
			const ids =
				query.claims?.flatMap((claim) => (claim.id === undefined ? [] : [claim.id])) ?? [];
			if (new Set(ids).size !== ids.length) fail("Claim identifiers must be unique");
			const claimPaths = query.claims?.map((claim) => JSON.stringify(claim.path)) ?? [];
			if (!allowDuplicatePaths && new Set(claimPaths).size !== claimPaths.length)
				fail("Claim queries must not repeat a path");
			if (
				query.claim_sets &&
				(!query.claims ||
					query.claims.some((claim) => claim.id === undefined) ||
					query.claim_sets.some((set) => set.some((id) => !ids.includes(id))))
			)
				fail("Claim sets must reference named claims");
			if (query.format === "mso_mdoc") {
				if (!nonblank.safeParse(query.meta.doctype_value).success)
					fail("mdoc queries require doctype_value");
				// VP Appendix B.2.4 defines this recognized mdoc field as a boolean.
				if (
					query.claims?.some(
						(claim) =>
							claim.intent_to_retain !== undefined && typeof claim.intent_to_retain !== "boolean",
					)
				)
					fail("mdoc intent_to_retain must be boolean");
				if (
					query.claims?.some(
						(claim) =>
							claim.path.length !== 2 || claim.path.some((part) => typeof part !== "string"),
					)
				)
					fail("mdoc claim paths must contain two strings");
			}
			if (
				query.format === "dc+sd-jwt" &&
				!z.array(nonblank).min(1).safeParse(query.meta.vct_values).success
			)
				fail("SD-JWT queries require vct_values");
			if (
				["jwt_vc_json", "jwt_vc_json-ld", "ldp_vc"].includes(query.format) &&
				!z.array(strings).min(1).safeParse(query.meta.type_values).success
			)
				fail("W3C queries require type_values");
		});

const dcqlQuerySchema = (allowDuplicatePaths: boolean) =>
	z
		.looseObject({
			credentials: z.array(credentialQuery(allowDuplicatePaths)).min(1),
			credential_sets: z
				.array(
					z.looseObject({ options: z.array(strings).min(1), required: z.boolean().optional() }),
				)
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
export const DcqlQuerySchema = dcqlQuerySchema(false);
/** Inbound duplicates are normalized after federation policy evaluation (§6.1). */
export const ReceivedDcqlQuerySchema = dcqlQuerySchema(true);
export type DcqlQuery = z.infer<typeof DcqlQuerySchema>;

/** Ignore later repeated paths, preserving references to their first occurrence. */
export function normalizeReceivedDcqlQuery(query: DcqlQuery): DcqlQuery {
	const copy = structuredClone(query);
	for (const credential of copy.credentials) {
		if (!credential.claims) continue;
		const paths = new Map<string, (typeof credential.claims)[number]>();
		const aliases = new Map<string, string>();
		credential.claims = credential.claims.filter((claim) => {
			const path = JSON.stringify(claim.path);
			const first = paths.get(path);
			if (!first) {
				paths.set(path, claim);
				return true;
			}
			// Structural validation already requires identifiers when claim_sets is present.
			if (claim.id !== undefined && first.id !== undefined) aliases.set(claim.id, first.id);
			return false;
		});
		if (credential.claim_sets)
			credential.claim_sets = credential.claim_sets.map((set) => [
				...new Set(set.map((id) => aliases.get(id) ?? id)),
			]);
	}
	return copy;
}

const formatCapabilities = z.record(
	nonblank,
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
	// Wallet §6.2.1 uses Federation §5.2.1 protocol keys, where kid is optional.
	// The provider integration convention uses the same public-key representation.
	jwks: MetadataJWKSetSchema.optional(),
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
	// Wallet §6.3.1 requires a unique identifier on every verifier key.
	jwks: JWKSetSchema.optional(),
	request_uris: z.array(https).min(1).optional(),
	response_uris: z.array(responseEndpoint).min(1).optional(),
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
	jsonRoot: boolean,
): void {
	const root: ClaimPathNode = { children: new Map() };
	for (const claim of claims) {
		if (jsonRoot && typeof claim.path[0] !== "string")
			ctx.addIssue({
				code: "custom",
				message: "JSON credential claim paths must start with an object member",
			});
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
		scope: scopeToken.optional(),
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
			["dc+sd-jwt", "jwt_vc_json", "jwt_vc_json-ld", "ldp_vc"].includes(configuration.format),
		);
		if (
			(configuration.cryptographic_binding_methods_supported !== undefined) !==
			(configuration.proof_types_supported !== undefined)
		)
			fail("Binding methods and proof types must be provided together");
		if (
			configuration.cryptographic_binding_methods_supported?.some(
				(method) => method.startsWith("did:") && !/^did:[a-z0-9]+$/.test(method),
			)
		)
			fail("DID binding methods must contain only did: and the method name");
		if (configuration.format === "mso_mdoc" && !nonblank.safeParse(configuration.doctype).success)
			fail("mdoc configuration requires doctype");
		if (configuration.format === "dc+sd-jwt" && !nonblank.safeParse(configuration.vct).success)
			fail("SD-JWT configuration requires vct");
		if (["jwt_vc_json", "jwt_vc_json-ld", "ldp_vc"].includes(configuration.format)) {
			const definition = z
				.looseObject({
					type: z.array(nonblank).min(1),
				})
				.safeParse(configuration.credential_definition);
			// VCI Appendix A.1.1.2 defines only type for jwt_vc_json; other members remain extensions.
			const context =
				configuration.format !== "jwt_vc_json" && definition.success
					? z
							.array(z.union([nonblank, object]))
							.min(1)
							.safeParse(definition.data["@context"])
					: undefined;
			if (
				!definition.success ||
				(context !== undefined &&
					(!context.success || context.data[0] !== "https://www.w3.org/2018/credentials/v1"))
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
			// OpenID4VCI §12.2.4 requires unique identifiers for request encryption keys.
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

/** Cross-field checks apply after superior metadata has completed the issuer's configuration. */
const effectiveCredentialIssuerMetadata = CredentialIssuerMetadataSchema.superRefine(
	(metadata, ctx) => {
		const encryption = metadata.credential_request_encryption;
		if (
			encryption &&
			!encryption.jwks.keys.some(
				(key) =>
					typeof key.alg === "string" &&
					key.alg.length > 0 &&
					key.alg !== "none" &&
					!isValidAlgorithm(key.alg) &&
					!otherSignatureAlgorithms.has(key.alg) &&
					(key.use === undefined || key.use === "enc") &&
					(key.key_ops === undefined ||
						key.key_ops.some((op) =>
							["encrypt", "wrapKey", "deriveKey", "deriveBits"].includes(op),
						)),
			)
		)
			ctx.addIssue({
				code: "custom",
				path: ["credential_request_encryption", "jwks"],
				message:
					"Request encryption requires an alg-bearing key that permits encryption or key agreement (OpenID4VCI §10)",
			});
		if (metadata.credential_response_encryption?.encryption_required && !encryption)
			ctx.addIssue({
				code: "custom",
				path: ["credential_request_encryption"],
				message: "Required response encryption needs request encryption support (OpenID4VCI §8.2)",
			});
	},
);

export const effectiveRoleSchemas = {
	openid_wallet_provider: WalletProviderMetadataSchema,
	openid_credential_issuer: effectiveCredentialIssuerMetadata,
	openid_credential_verifier: CredentialVerifierMetadataSchema.extend({
		dcql_queries: z.array(ReceivedDcqlQuerySchema).min(1).optional(),
	}),
} as const;

export const roleSchemas = {
	openid_wallet_provider: WalletProviderMetadataSchema,
	openid_credential_issuer: CredentialIssuerMetadataSchema,
	openid_credential_verifier: CredentialVerifierMetadataSchema,
} as const;
/** Federation §5 permits superiors to complete top-level role metadata. */
export const publicationRoleSchemas = {
	openid_wallet_provider: WalletProviderMetadataSchema.partial(),
	openid_credential_issuer: CredentialIssuerMetadataSchema.partial(),
	openid_credential_verifier: CredentialVerifierMetadataSchema.partial(),
} as const;

/** Supplied publication fields; Superiors may complete missing top-level metadata. */
export type WalletProviderPublicationMetadata = z.infer<
	typeof publicationRoleSchemas.openid_wallet_provider
>;
export type CredentialIssuerPublicationMetadata = z.infer<
	typeof publicationRoleSchemas.openid_credential_issuer
>;
export type CredentialVerifierPublicationMetadata = z.infer<
	typeof publicationRoleSchemas.openid_credential_verifier
>;
export type WalletRoleType = keyof typeof roleSchemas;
