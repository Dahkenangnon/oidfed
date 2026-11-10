import {
	type EntityContext,
	type EntityRole,
	entityId,
	err,
	type FederationError,
	FederationErrorCode,
	type JWKSet,
	type JwtSigner,
	nowSeconds,
	ok,
	type Result,
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
import {
	effectiveRoleSchemas,
	publicationRoleSchemas,
	roleSchemas,
	type WalletRoleType,
} from "./metadata.js";
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
	type TrustedWalletEntity,
	trustedEntity,
	type WalletTrustOptions,
} from "./trust.js";

export interface WalletRoleConfig {
	readonly metadata?: Readonly<Record<string, unknown>>;
	readonly trustAnchors?: TrustAnchorSet;
}

abstract class WalletRole implements EntityRole {
	abstract readonly type: WalletRoleType;
	readonly metadata: Record<string, unknown>;
	protected context?: EntityContext;
	constructor(readonly config: WalletRoleConfig = {}) {
		this.metadata = structuredClone(config.metadata ?? {});
	}
	initialize(context: EntityContext): void {
		if (this.context && this.context !== context)
			throw new Error("Create a separate wallet role instance for each host");
		this.context = context;
	}
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
	protected anchors(options?: WalletTrustOptions): TrustAnchorSet {
		const anchors = options?.trustAnchors ?? this.config.trustAnchors ?? this.context?.trustAnchors;
		if (!anchors?.size) throw new Error("Pinned trust anchors are required");
		return anchors;
	}
	protected options<T extends WalletTrustOptions>(options: T): T {
		return { ...this.context?.options, ...options };
	}
}

async function signingEvidence(id: string, options: WalletTrustOptions): Promise<Result<true>> {
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
	const candidate = paths.value[0];
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
		? ok(true)
		: failure("Attached signing chain is invalid or belongs to another entity");
}

abstract class AttestationConsumer extends WalletRole {
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
		);
		if (!accepted.ok) return accepted;
		return provider.value.trustChain.expiresAt > nowSeconds(options.clock) &&
			!options.signal?.aborted
			? provider
			: failure("Provider evidence expired or was cancelled");
	}
	static async verifyWalletAttestation(
		jwt: string,
		anchors: TrustAnchorSet,
		options: WalletAttestationVerificationOptions = {},
	): Promise<Result<VerifiedWalletAttestation>> {
		const scope = operationOptions(options);
		return scope.ok ? verifyAttestation(jwt, anchors, scope.value) : scope;
	}
	static async authenticateWallet(
		attestation: string,
		proof: string,
		anchors: TrustAnchorSet,
		options: AuthenticateWalletOptions,
	): Promise<Result<VerifiedWalletAttestation>> {
		const scope = operationOptions(options);
		return scope.ok ? authenticateWallet(attestation, proof, anchors, scope.value) : scope;
	}
	verifyWalletAttestation(jwt: string, options: WalletAttestationVerificationOptions = {}) {
		return AttestationConsumer.verifyWalletAttestation(
			jwt,
			this.anchors(options),
			this.options(options),
		);
	}
	authenticateWallet(attestation: string, proof: string, options: AuthenticateWalletOptions) {
		return AttestationConsumer.authenticateWallet(
			attestation,
			proof,
			this.anchors(options),
			this.options(options),
		);
	}
	verifyProviderAttestation(
		attestation: unknown,
		providerId: string,
		options: AttestationVerificationOptions,
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
	static parseMetadata(metadata: unknown) {
		return roleSchemas.openid_wallet_provider.safeParse(metadata);
	}
	static async discover(id: string, anchors: TrustAnchorSet, options: WalletTrustOptions = {}) {
		const scope = operationOptions(options);
		return scope.ok ? trustedEntity("openid_wallet_provider", id, anchors, scope.value) : scope;
	}
	static async createWalletAttestation(
		id: string,
		params: CreateWalletAttestationParams,
		signer: JwtSigner,
		options: WalletTrustOptions = {},
	): Promise<Result<string>> {
		const scope = operationOptions(options);
		if (!scope.ok) return scope;
		const evidence = await signingEvidence(id, scope.value);
		return evidence.ok ? createAttestation(id, params, signer, scope.value) : evidence;
	}
	discover(id: string, options: WalletTrustOptions = {}) {
		return WalletProviderRole.discover(id, this.anchors(options), this.options(options));
	}
	createWalletAttestation(
		params: CreateWalletAttestationParams,
		signer: JwtSigner,
		options: WalletTrustOptions = {},
	) {
		return WalletProviderRole.createWalletAttestation(this.identity().entityId, params, signer, {
			...this.options(options),
			...(options.trustChain ? { trustAnchors: this.anchors(options) } : {}),
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
	static parseMetadata(metadata: unknown) {
		return effectiveRoleSchemas.openid_credential_issuer.safeParse(metadata);
	}
	static async discover(
		id: string,
		anchors: TrustAnchorSet,
		options: CredentialIssuerDiscoveryOptions = {},
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
			const paths = server === id ? ok([]) : await candidates(server, anchors, nestedOptions);
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
				if (metadata?.issuer === server)
					found = { entityId: server, metadata, trustChain: issuer.value.trustChain };
			} else {
				for (const path of paths.value) {
					const checked = await validateTrustChain(path.statements, anchors, {
						...scoped,
						entityConfigurations: path.entityConfigurations,
					});
					const metadata = checked.valid
						? checked.chain.resolvedMetadata.oauth_authorization_server
						: undefined;
					if (checked.valid && checked.chain.entityId === server && metadata?.issuer === server) {
						found = { entityId: server, metadata, trustChain: checked.chain };
						break;
					}
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
	discover(id: string, options: CredentialIssuerDiscoveryOptions = {}) {
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
	static parseMetadata(metadata: unknown) {
		return roleSchemas.openid_credential_verifier.safeParse(metadata);
	}
	static async discover(id: string, anchors: TrustAnchorSet, options: WalletTrustOptions = {}) {
		const scope = operationOptions(options);
		return scope.ok ? trustedEntity("openid_credential_verifier", id, anchors, scope.value) : scope;
	}
	static async prepareAuthorizationRequest(
		outer: WalletAuthorizationRequest,
		anchors: TrustAnchorSet,
		options: AuthorizationRequestOptions = {},
	): Promise<Result<PreparedAuthorizationRequest>> {
		const scope = operationOptions(options);
		return scope.ok ? prepareRequest(outer, anchors, scope.value) : scope;
	}
	static completeAuthorizationRequest(
		prepared: PreparedAuthorizationRequest,
		jwt: string,
		context?: AuthorizationRequestContext,
	): Promise<Result<ValidatedWalletRequest>> {
		return completeRequest(prepared, jwt, context);
	}
	static async createAuthorizationRequest(
		id: string,
		request: Readonly<Record<string, unknown>>,
		signer: JwtSigner,
		options: AuthorizationRequestCreationOptions = {},
	) {
		try {
			entityId(id);
		} catch {
			return failure("Invalid signing entity identifier");
		}
		const scope = operationOptions(options);
		return scope.ok ? createRequest(id, request, signer, scope.value) : scope;
	}
	static validateResponseRedirect(result: ValidatedWalletRequest, uri: string): Result<true> {
		return validateResponseRedirect(result, uri);
	}
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
		);
		if (!accepted.ok) return accepted;
		if (issuer.value.trustChain.expiresAt <= nowSeconds(options.clock) || options.signal?.aborted)
			return failure("Credential issuer evidence expired or was cancelled");
		return issuer;
	}
	discover(id: string, options: WalletTrustOptions = {}) {
		return CredentialVerifierRole.discover(id, this.anchors(options), this.options(options));
	}
	prepareAuthorizationRequest(
		outer: WalletAuthorizationRequest,
		options: AuthorizationRequestOptions = {},
	) {
		return CredentialVerifierRole.prepareAuthorizationRequest(
			outer,
			this.anchors(options),
			this.options(options),
		);
	}
	completeAuthorizationRequest(
		prepared: PreparedAuthorizationRequest,
		jwt: string,
		context?: AuthorizationRequestContext,
	) {
		return CredentialVerifierRole.completeAuthorizationRequest(prepared, jwt, context);
	}
	createAuthorizationRequest(
		request: Readonly<Record<string, unknown>>,
		signer: JwtSigner,
		options: AuthorizationRequestCreationOptions = {},
	) {
		return CredentialVerifierRole.createAuthorizationRequest(
			this.identity().entityId,
			request,
			signer,
			{
				...this.options(options),
				...(options.trustChain ? { trustAnchors: this.anchors(options) } : {}),
			},
		);
	}
	verifyCredential(credential: unknown, issuerId: string, options: CredentialVerificationOptions) {
		return CredentialVerifierRole.verifyCredential(
			credential,
			issuerId,
			this.anchors(options),
			this.options(options),
		);
	}
}
