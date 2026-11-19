import {
	bindFederationOptions,
	cloneData,
	selectSigningEntry,
	signingPublication,
	validateSigningPurposes,
} from "@oidfed/core";
import type { KeyPurpose, KeyringEntry } from "@oidfed/crypto";
/** Composable Wallet Provider, Credential Issuer, and Credential Verifier federation roles. */

import {
	assessEntity,
	type ClientAttestationError,
	clientAttestationHeaders,
	createAttestationChallengeHandler,
	createClientAttestationProof,
	type EntityAssessmentOptions,
	type EntityContext,
	type EntityRole,
	entityId,
	err,
	type FederationError,
	FederationErrorCode,
	fetchAttestationChallenge,
	type JWKSet,
	nowSeconds,
	ok,
	parseOAuthAuthorizationServerMetadata,
	type Result,
	readAttestationChallenge,
	selectTrustChain,
	serializeClientAttestation,
	shortestChain,
	type TrustAnchorSet,
	validateTrustChain,
} from "@oidfed/core";
import {
	type AuthenticateWalletOptions,
	authenticateWallet,
	type CreateWalletAttestationParams,
	createAttestation,
	invokePolicy,
	type VerifiedWalletAttestation,
	verifyAttestation,
	type WalletAttestationVerificationOptions,
} from "./attestation.js";
import { effectiveRoleSchemas, publicationRoleSchemas, type WalletRoleType } from "./metadata.js";
import {
	type AuthorizationRequestContext,
	type AuthorizationRequestCreationOptions,
	type AuthorizationRequestOptions,
	completeRequest,
	createRequest,
	type PreparedAuthorizationRequest,
	prepareRequest,
	type ValidatedWalletRequest,
	validateResponseRedirect,
	type WalletAuthorizationRequest,
} from "./request.js";
import {
	candidates,
	failure,
	operationExhausted,
	operationOptions,
	protocolKeys,
	requirePublishedProtocolSigner,
	roleMetadata,
	type TrustedWalletEntity,
	trustedEntity,
	type WalletTrustOptions,
} from "./trust.js";

/** Metadata is copied at construction. Instance operations combine host, role, then per-call options; attach the role before operations needing its signing identity. */
export interface WalletRoleConfig {
	/** Map walletAttestation and authorizationRequest to the host keyring as needed. */
	readonly signing?: Readonly<
		Partial<Record<"walletAttestation" | "authorizationRequest", KeyPurpose>>
	>;
	readonly options?: Omit<WalletTrustOptions, "engine">;
	readonly metadata?: Readonly<Record<string, unknown>>;
	readonly trustAnchors?: TrustAnchorSet;
}

abstract class WalletRole implements EntityRole {
	static createClientAttestationProof = createClientAttestationProof;
	static clientAttestationHeaders = clientAttestationHeaders;
	static serializeClientAttestation = serializeClientAttestation;
	static fetchAttestationChallenge = fetchAttestationChallenge;
	static readAttestationChallenge = readAttestationChallenge;
	static createAttestationChallengeHandler = createAttestationChallengeHandler;

	/**
	 * Assess a participant with role-appropriate metadata and independently configured accreditation
	 * trust.
	 */
	static async assessEntity(
		target: string,
		type: WalletRoleType,
		anchors: TrustAnchorSet,
		options: EntityAssessmentOptions & WalletTrustOptions,
	) {
		const supplied = options.trustChain ?? options.entityChains?.get(target);
		if (supplied) options = { ...options, trustChain: supplied };
		const assessed = await assessEntity(
			entityId(target),
			anchors,
			options.mode === "resolver"
				? options
				: {
						...options,
						chainSelection: (chains) => {
							// Issuer accreditation is independent of the subject's wallet role (§17.5).
							const eligible = chains.filter(
								(chain) =>
									chain.entityId !== target || roleMetadata(type, target, chain, options).ok,
							);
							if (!eligible.length) throw new Error("No chain supplies valid wallet metadata");
							return (options.chainSelection ?? shortestChain)(eligible);
						},
					},
		);
		if (!assessed.ok) return assessed;
		const metadata = roleMetadata(type, target, assessed.value, options);
		return metadata.ok ? assessed : metadata;
	}
	/**
	 * Assess a participant with role-appropriate metadata and independently configured accreditation
	 * trust.
	 */
	assessEntity(
		target: string,
		type: WalletRoleType,
		options: Omit<EntityAssessmentOptions & WalletTrustOptions, "engine"> = {},
	) {
		return WalletRole.assessEntity(
			target,
			type,
			this.anchors(options),
			bindFederationOptions(
				this.identity().crypto,
				this.context?.options,
				this.config.options,
				options,
			),
		);
	}
	abstract readonly type: WalletRoleType;
	readonly metadata: Record<string, unknown>;
	protected context?: EntityContext;
	/** Detach supplied role metadata while retaining host-provided options and dependencies. */
	constructor(readonly config: WalletRoleConfig = {}) {
		this.metadata = cloneData(config.metadata ?? {});
	}
	/** Attach the role to one federation host; reuse with a different host context throws. */
	async initialize(context: EntityContext): Promise<void> {
		if (this.context && this.context !== context)
			throw new Error("Create a separate wallet role instance for each host");
		validateSigningPurposes(
			this.config.signing,
			this.type === "openid_wallet_provider"
				? ["walletAttestation"]
				: this.type === "openid_credential_verifier"
					? ["authorizationRequest"]
					: [],
		);
		await signingPublication(context, this.config.signing);
		this.context = context;
	}
	/** Rebuild managed protocol keys for an Entity Configuration publication. */
	publicationMetadata(
		context: EntityContext,
		entries?: ReadonlyMap<string, KeyringEntry>,
	): Promise<Record<string, unknown>> {
		return signingPublication(context, this.config.signing, entries);
	}

	/**
	 * Check composed publication fields and bind a supplied credential_issuer to the host identity.
	 */
	validateMetadata(metadata: Readonly<Record<string, unknown>>, context: EntityContext): void {
		const parsed = publicationRoleSchemas[this.type].safeParse(metadata);
		if (!parsed.success)
			throw new TypeError(`Invalid ${this.type} metadata: ${parsed.error.message}`);
		if (
			this.type === "openid_credential_issuer" &&
			parsed.data.credential_issuer !== undefined &&
			parsed.data.credential_issuer !== context.entityId
		)
			throw new TypeError("credential_issuer must equal the host entity identifier");
	}
	protected identity(): EntityContext {
		if (!this.context)
			throw new Error("Attach the role to a federation host before using instance operations");
		return this.context;
	}
	protected anchors(options?: Omit<WalletTrustOptions, "engine">): TrustAnchorSet {
		const anchors =
			options?.trustAnchors ??
			this.config.trustAnchors ??
			this.config.options?.trustAnchors ??
			this.context?.trustAnchors;
		if (!anchors?.size) throw new Error("Pinned trust anchors are required");
		return anchors;
	}
	protected options<T extends Omit<WalletTrustOptions, "engine">>(
		options: T,
	): T & WalletTrustOptions {
		return {
			...options,
			...bindFederationOptions(
				this.identity().crypto,
				this.identity().options,
				this.config.options,
				options,
			),
		};
	}
}

async function signingEvidence(
	id: string,
	signer: KeyringEntry,
	options: WalletTrustOptions,
): Promise<Result<true>> {
	try {
		entityId(id);
	} catch {
		return failure("Invalid signing entity identifier");
	}
	if (!options.trustChain) return ok(true);
	if (!options.trustAnchors?.size)
		return failure("Attaching a trust chain requires pinned anchors");
	const paths = await candidates(id, options.trustAnchors, options);
	if (!paths.ok) return paths;
	const candidate = paths.value.chains[0];
	if (!candidate) return failure("No attached signing chain");
	const checked = await validateTrustChain(candidate.statements, options.trustAnchors, {
		...options,
		entityConfigurations: candidate.entityConfigurations,
		verboseErrors: true,
	});
	if (!checked.valid)
		return failure(
			`Attached signing chain is invalid: ${checked.errors.map((error) => error.message).join("; ")}`,
		);
	return checked.chain.entityId === id
		? requirePublishedProtocolSigner(checked.chain, "openid_wallet_provider", signer, options)
		: failure("Attached signing chain is invalid or belongs to another entity");
}

abstract class AttestationConsumer extends WalletRole {
	/**
	 * Establish provider trust and invoke the required host verifier for an alternative attestation
	 * format.
	 */
	static async verifyProviderAttestation(
		attestation: unknown,
		providerId: string,
		anchors: TrustAnchorSet,
		options: AttestationVerificationOptions,
	): Promise<Result<TrustedWalletEntity>> {
		const scope = operationOptions(options);
		if (!scope.ok) return scope;
		const scoped = scope.value;
		const provider = await trustedEntity("openid_wallet_provider", providerId, anchors, scoped);
		if (!provider.ok) return provider;
		// Wallet §8.5 requires attestation verification with federation-provided material.
		const keys = await protocolKeys(provider.value, "openid_wallet_provider", scoped);
		if (!keys.ok) return keys;
		const accepted = await invokePolicy(
			options.verifyAttestation,
			{ attestation, provider: provider.value, keys: keys.value },
			scoped,
			"Wallet Attestation verification",
		);
		if (!accepted.ok) return accepted;
		return provider.value.trustChain.expiresAt > nowSeconds(options.clock) &&
			!options.signal?.aborted
			? provider
			: failure("Provider evidence expired or was cancelled");
	}
	/**
	 * Verify a JWT Wallet Attestation with trusted provider protocol keys; holder authentication is
	 * separate.
	 */
	static async verifyWalletAttestation(
		jwt: string,
		anchors: TrustAnchorSet,
		options: WalletAttestationVerificationOptions,
	): Promise<Result<VerifiedWalletAttestation, ClientAttestationError>> {
		const scope = operationOptions(options);
		return scope.ok ? verifyAttestation(jwt, anchors, scope.value) : scope;
	}
	/**
	 * Authenticate the attestation and holder proof using configured replay and wallet acceptance
	 * policies.
	 */
	static async authenticateWallet(
		attestation: string,
		proof: string,
		anchors: TrustAnchorSet,
		options: AuthenticateWalletOptions,
	): Promise<Result<VerifiedWalletAttestation, ClientAttestationError>> {
		const scope = operationOptions(options);
		return scope.ok ? authenticateWallet(attestation, proof, anchors, scope.value) : scope;
	}
	/**
	 * Verify a JWT Wallet Attestation with trusted provider protocol keys; holder authentication is
	 * separate.
	 */
	verifyWalletAttestation(
		jwt: string,
		options: Omit<WalletAttestationVerificationOptions, "engine"> = {},
	) {
		return AttestationConsumer.verifyWalletAttestation(
			jwt,
			this.anchors(options),
			this.options(options),
		);
	}
	/**
	 * Authenticate the attestation and holder proof using configured replay and wallet acceptance
	 * policies.
	 */
	authenticateWallet(
		attestation: string,
		proof: string,
		options: Omit<AuthenticateWalletOptions, "engine">,
	) {
		return AttestationConsumer.authenticateWallet(
			attestation,
			proof,
			this.anchors(options),
			this.options(options),
		);
	}
	/**
	 * Establish provider trust and invoke the required host verifier for an alternative attestation
	 * format.
	 */
	verifyProviderAttestation(
		attestation: unknown,
		providerId: string,
		options: Omit<AttestationVerificationOptions, "engine">,
	) {
		return AttestationConsumer.verifyProviderAttestation(
			attestation,
			providerId,
			this.anchors(options),
			this.options(options),
		);
	}
}

export interface AttestationVerificationOptions extends WalletTrustOptions {
	/** Verify the attestation with the supplied keys and apply format-specific checks before accepting it. */
	readonly verifyAttestation: (
		context: { attestation: unknown; provider: TrustedWalletEntity; keys: JWKSet },
		signal?: AbortSignal,
	) => boolean | Promise<boolean>;
}

async function adapterKeys(
	entity: TrustedWalletEntity,
	type: WalletRoleType,
	options: WalletTrustOptions,
): Promise<Result<JWKSet | undefined>> {
	return ["jwks", "jwks_uri", "signed_jwks_uri"].some(
		(field) => entity.metadata[field] !== undefined,
	)
		? protocolKeys(entity, type, options)
		: ok(undefined);
}

export class WalletProviderRole extends WalletRole {
	readonly type = "openid_wallet_provider";
	/**
	 * Return a parse result for effective protocol metadata. Establish federation trust separately.
	 */
	static parseMetadata(metadata: unknown) {
		return effectiveRoleSchemas.openid_wallet_provider.safeParse(metadata);
	}
	/**
	 * Return a parse result for supplied publication fields. A Superior may complete omitted
	 * requirements; establish federation trust separately.
	 */
	static parsePublicationMetadata(metadata: unknown) {
		return publicationRoleSchemas.openid_wallet_provider.safeParse(metadata);
	}
	/** Establish Wallet Provider trust and validate its effective federation metadata. */
	static async discover(id: string, anchors: TrustAnchorSet, options: WalletTrustOptions) {
		const scope = operationOptions(options);
		return scope.ok ? trustedEntity("openid_wallet_provider", id, anchors, scope.value) : scope;
	}
	/**
	 * Create a signed instance attestation; validate any supplied signing chain before attaching it.
	 */
	static async createWalletAttestation(
		id: string,
		params: CreateWalletAttestationParams,
		signer: KeyringEntry,
		options: WalletTrustOptions,
	): Promise<Result<string>> {
		const scope = operationOptions(options);
		if (!scope.ok) return scope;
		const evidence = await signingEvidence(id, signer, scope.value);
		return evidence.ok ? createAttestation(id, params, signer, scope.value) : evidence;
	}
	/** Establish Wallet Provider trust and validate its effective federation metadata. */
	discover(id: string, options: Omit<WalletTrustOptions, "engine"> = {}) {
		return WalletProviderRole.discover(id, this.anchors(options), this.options(options));
	}
	/**
	 * Create a signed instance attestation; validate any supplied signing chain before attaching it.
	 */
	async createWalletAttestation(
		params: CreateWalletAttestationParams,
		options: Omit<WalletTrustOptions, "engine"> = {},
	) {
		const effective = this.options(options);
		if (!this.config.signing?.walletAttestation)
			return failure("Configure the walletAttestation signing purpose");
		const signer = await selectSigningEntry(
			this.identity().crypto,
			this.config.signing?.walletAttestation,
			{ issuer: this.identity().entityId, subject: params.subject },
		);
		return WalletProviderRole.createWalletAttestation(this.identity().entityId, params, signer, {
			...effective,
			...(effective.trustChain ? { trustAnchors: this.anchors(options) } : {}),
		});
	}
}

export interface CredentialIssuerDiscoveryOptions extends WalletTrustOptions {
	/** VCI §12.2.4 permits server selection; all preserves strict discovery. */
	readonly authorizationServerPolicy?: "all" | "available";
}

export interface DiscoveredCredentialIssuer extends TrustedWalletEntity {
	readonly authorizationServerErrors: readonly { entityId: string; error: FederationError }[];
	readonly authorizationServers: readonly TrustedWalletEntity[];
}

export class CredentialIssuerRole extends AttestationConsumer {
	readonly type = "openid_credential_issuer";
	/**
	 * Return a parse result for effective protocol metadata. Establish federation trust separately.
	 */
	static parseMetadata(metadata: unknown) {
		return effectiveRoleSchemas.openid_credential_issuer.safeParse(metadata);
	}
	/**
	 * Return a parse result for supplied publication fields. A Superior may complete omitted
	 * requirements; establish federation trust separately.
	 */
	static parsePublicationMetadata(metadata: unknown) {
		return publicationRoleSchemas.openid_credential_issuer.safeParse(metadata);
	}
	/**
	 * Establish issuer trust and discover usable authorization servers under the configured
	 * availability policy.
	 */
	static async discover(
		id: string,
		anchors: TrustAnchorSet,
		options: CredentialIssuerDiscoveryOptions,
	): Promise<Result<DiscoveredCredentialIssuer>> {
		if (
			options.authorizationServerPolicy !== undefined &&
			!["all", "available"].includes(options.authorizationServerPolicy)
		)
			return failure("Invalid authorizationServerPolicy");
		const scope = operationOptions(options);
		if (!scope.ok) return scope;
		const scoped = scope.value;
		const issuer = await trustedEntity("openid_credential_issuer", id, anchors, scoped);
		if (!issuer.ok) return issuer;
		const servers = (issuer.value.metadata.authorization_servers ?? [id]) as string[];
		const authorizationServers: TrustedWalletEntity[] = [];
		const authorizationServerErrors: { entityId: string; error: FederationError }[] = [];
		for (const server of new Set(servers)) {
			const { trustChain: _, ...nestedOptions } = scoped;
			const paths =
				server === id ? ok({ chains: [] }) : await candidates(server, anchors, nestedOptions);
			if (!paths.ok) {
				if (
					options.authorizationServerPolicy !== "available" ||
					scoped.signal?.aborted ||
					operationExhausted(scoped)
				)
					return paths;
				authorizationServerErrors.push({ entityId: server, error: paths.error });
				continue;
			}
			let found: TrustedWalletEntity | undefined;
			if (server === id) {
				const metadata = issuer.value.trustChain.resolvedMetadata.oauth_authorization_server;
				const parsed = parseOAuthAuthorizationServerMetadata(metadata, { profile: "openid4vci" });
				if (parsed.success && parsed.data.issuer === server)
					found = { entityId: server, metadata: parsed.data, trustChain: issuer.value.trustChain };
			} else {
				const eligible: TrustedWalletEntity[] = [];
				for (const path of paths.value.chains) {
					const checked = await validateTrustChain(path.statements, anchors, {
						...scoped,
						entityConfigurations: path.entityConfigurations,
					});
					const metadata = checked.valid
						? checked.chain.resolvedMetadata.oauth_authorization_server
						: undefined;
					const parsed = parseOAuthAuthorizationServerMetadata(metadata, { profile: "openid4vci" });
					if (
						checked.valid &&
						checked.chain.entityId === server &&
						parsed.success &&
						parsed.data.issuer === server
					) {
						found = { entityId: server, metadata: parsed.data, trustChain: checked.chain };
						eligible.push(found);
						if (!scoped.chainSelection) break;
					}
				}
				if (scoped.chainSelection && eligible.length) {
					const selected = selectTrustChain(
						eligible.map((entity) => entity.trustChain),
						scoped,
					);
					if (!selected.ok) return selected;
					found = eligible.find((entity) => entity.trustChain === selected.value);
				}
			}
			if (scoped.signal?.aborted || operationExhausted(scoped))
				return failure(
					"Authorization server discovery was cancelled or exhausted its fetch budget",
				);
			if (!found) {
				const rejected = {
					code: FederationErrorCode.InvalidMetadata,
					description: `Authorization server ${server} lacks valid federation metadata`,
				};
				if (options.authorizationServerPolicy !== "available") return err(rejected);
				authorizationServerErrors.push({ entityId: server, error: rejected });
				continue;
			}
			authorizationServers.push(found);
		}
		if (!authorizationServers.length) return failure("No usable authorization server remains");
		// OpenID4VCI §12.2.4 applies this condition to each configuration without scope.
		const configurations = issuer.value.metadata.credential_configurations_supported as Record<
			string,
			{ scope?: string }
		>;
		if (
			Object.values(configurations).some((configuration) => configuration.scope === undefined) &&
			!authorizationServers.some((server) => {
				const supported = server.metadata.authorization_details_types_supported;
				return (
					Array.isArray(supported) &&
					supported.every((value) => typeof value === "string") &&
					supported.includes("openid_credential")
				);
			})
		)
			return err({
				code: FederationErrorCode.InvalidMetadata,
				description:
					"Scopeless credential configurations require an authorization server supporting openid_credential authorization details",
			});
		if (
			scoped.signal?.aborted ||
			operationExhausted(scoped) ||
			issuer.value.trustChain.expiresAt <= nowSeconds(scoped.clock) ||
			authorizationServers.some((server) => server.trustChain.expiresAt <= nowSeconds(scoped.clock))
		)
			return failure("Issuer discovery evidence expired or operation stopped");
		return ok({ ...issuer.value, authorizationServers, authorizationServerErrors });
	}
	/**
	 * Establish issuer trust and discover usable authorization servers under the configured
	 * availability policy.
	 */
	discover(id: string, options: Omit<CredentialIssuerDiscoveryOptions, "engine"> = {}) {
		return CredentialIssuerRole.discover(id, this.anchors(options), this.options(options));
	}
}

export interface CredentialVerificationOptions extends WalletTrustOptions {
	readonly verifyCredential: (
		context: { credential: unknown; issuer: TrustedWalletEntity; keys: JWKSet | undefined },
		signal?: AbortSignal,
	) => boolean | Promise<boolean>;
}

export class CredentialVerifierRole extends AttestationConsumer {
	readonly type = "openid_credential_verifier";
	/**
	 * Return a parse result for effective protocol metadata. Establish federation trust separately.
	 */
	static parseMetadata(metadata: unknown) {
		return effectiveRoleSchemas.openid_credential_verifier.safeParse(metadata);
	}
	/**
	 * Return a parse result for supplied publication fields. A Superior may complete omitted
	 * requirements; establish federation trust separately.
	 */
	static parsePublicationMetadata(metadata: unknown) {
		return publicationRoleSchemas.openid_credential_verifier.safeParse(metadata);
	}
	/** Establish Credential Verifier trust and validate its effective federation metadata. */
	static async discover(id: string, anchors: TrustAnchorSet, options: WalletTrustOptions) {
		const scope = operationOptions(options);
		return scope.ok ? trustedEntity("openid_credential_verifier", id, anchors, scope.value) : scope;
	}
	/** Establish candidate federation evidence. Returns a process-local handle; completion still validates the signed request and contextual policies. */
	static async prepareAuthorizationRequest(
		outer: WalletAuthorizationRequest,
		anchors: TrustAnchorSet,
		options: AuthorizationRequestOptions,
	): Promise<Result<PreparedAuthorizationRequest>> {
		const scope = operationOptions(options);
		return scope.ok ? prepareRequest(outer, anchors, scope.value) : scope;
	}
	/** Complete the original, unexpired preparation handle with its signed JWT. Returns a Result; copied or deserialized handles are rejected. */
	static completeAuthorizationRequest(
		prepared: PreparedAuthorizationRequest,
		jwt: string,
		context?: AuthorizationRequestContext,
	): Promise<Result<ValidatedWalletRequest>> {
		return completeRequest(prepared, jwt, context);
	}
	/**
	 * Create a signed federation presentation request; the host supplies its signer and protocol
	 * parameters.
	 */
	static async createAuthorizationRequest(
		id: string,
		request: Readonly<Record<string, unknown>>,
		signer: KeyringEntry,
		options: AuthorizationRequestCreationOptions,
	) {
		try {
			entityId(id);
		} catch {
			return failure("Invalid signing entity identifier");
		}
		const scope = operationOptions(options);
		return scope.ok ? createRequest(id, request, signer, scope.value) : scope;
	}
	/** Check a redirect using current metadata retained for an original validated request result. */
	static validateResponseRedirect(result: ValidatedWalletRequest, uri: string): Result<true> {
		return validateResponseRedirect(result, uri);
	}
	/** Establish issuer trust and invoke the host verifier. The host owns credential format, proof, and status checks; this returns trusted issuer evidence on success. */
	static async verifyCredential(
		credential: unknown,
		issuerId: string,
		anchors: TrustAnchorSet,
		options: CredentialVerificationOptions,
	): Promise<Result<TrustedWalletEntity>> {
		const scope = operationOptions(options);
		if (!scope.ok) return scope;
		const scoped = scope.value;
		const issuer = await trustedEntity("openid_credential_issuer", issuerId, anchors, scoped);
		if (!issuer.ok) return issuer;
		const keys = await adapterKeys(issuer.value, "openid_credential_issuer", scoped);
		if (!keys.ok) return keys;
		const accepted = await invokePolicy(
			options.verifyCredential,
			{ credential, issuer: issuer.value, keys: keys.value },
			scoped,
			"Digital Credential verification",
		);
		if (!accepted.ok) return accepted;
		if (issuer.value.trustChain.expiresAt <= nowSeconds(options.clock) || options.signal?.aborted)
			return failure("Credential issuer evidence expired or was cancelled");
		return issuer;
	}
	/** Establish Credential Verifier trust and validate its effective federation metadata. */
	discover(id: string, options: Omit<WalletTrustOptions, "engine"> = {}) {
		return CredentialVerifierRole.discover(id, this.anchors(options), this.options(options));
	}
	/** Prepare using configured anchors and merged options. Keep the returned handle for completeAuthorizationRequest; preparation is not acceptance. */
	prepareAuthorizationRequest(
		outer: WalletAuthorizationRequest,
		options: Omit<AuthorizationRequestOptions, "engine"> = {},
	) {
		return CredentialVerifierRole.prepareAuthorizationRequest(
			outer,
			this.anchors(options),
			this.options(options),
		);
	}
	/** Complete an original preparation handle before expiry. The returned Result covers federation checks, not presentation processing. */
	completeAuthorizationRequest(
		prepared: PreparedAuthorizationRequest,
		jwt: string,
		context?: AuthorizationRequestContext,
	) {
		return CredentialVerifierRole.completeAuthorizationRequest(prepared, jwt, context);
	}
	/**
	 * Create a signed federation presentation request; the host supplies its signer and protocol
	 * parameters.
	 */
	async createAuthorizationRequest(
		request: Readonly<Record<string, unknown>>,
		options: Omit<AuthorizationRequestCreationOptions, "engine"> = {},
	) {
		const effective = this.options(options);
		if (!this.config.signing?.authorizationRequest)
			return failure("Configure the authorizationRequest signing purpose");
		const signer = await selectSigningEntry(
			this.identity().crypto,
			this.config.signing?.authorizationRequest,
			{ issuer: this.identity().entityId },
		);
		return CredentialVerifierRole.createAuthorizationRequest(
			this.identity().entityId,
			request,
			signer,
			{
				...effective,
				...(effective.trustChain ? { trustAnchors: this.anchors(options) } : {}),
			},
		);
	}
	/**
	 * Use configured issuer trust and the required host callback for format, proof, and status
	 * verification.
	 */
	verifyCredential(
		credential: unknown,
		issuerId: string,
		options: Omit<CredentialVerificationOptions, "engine">,
	) {
		return CredentialVerifierRole.verifyCredential(
			credential,
			issuerId,
			this.anchors(options),
			this.options(options),
		);
	}
}
