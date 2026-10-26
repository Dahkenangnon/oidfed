import {
	type EntityContext,
	type EntityRole,
	entityId,
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
} from "./attestation.js";
import { roleSchemas, type WalletRoleType } from "./metadata.js";
import {
	type AuthorizationRequestContext,
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
		const parsed = roleSchemas[this.type].safeParse(metadata);
		if (!parsed.success)
			throw new TypeError(`Invalid ${this.type} metadata: ${parsed.error.message}`);
		if (
			this.type === "openid_credential_issuer" &&
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
	const checked = await validateTrustChain(options.trustChain, options.trustAnchors, options);
	return checked.valid && checked.chain.entityId === id
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
		const scoped = operationOptions(options);
		const provider = await trustedEntity("openid_wallet_provider", providerId, anchors, scoped);
		if (!provider.ok) return provider;
		const keys = await adapterKeys(provider.value, "openid_wallet_provider", scoped);
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
		options: WalletTrustOptions = {},
	): Promise<Result<VerifiedWalletAttestation>> {
		return verifyAttestation(jwt, anchors, operationOptions(options));
	}
	static async authenticateWallet(
		attestation: string,
		proof: string,
		anchors: TrustAnchorSet,
		options: AuthenticateWalletOptions,
	): Promise<Result<VerifiedWalletAttestation>> {
		return authenticateWallet(attestation, proof, anchors, {
			...options,
			...operationOptions(options),
		});
	}
	verifyWalletAttestation(jwt: string, options: WalletTrustOptions = {}) {
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
	readonly verifyAttestation: (
		context: { attestation: unknown; provider: TrustedWalletEntity; keys: JWKSet | undefined },
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
	static discover(id: string, anchors: TrustAnchorSet, options: WalletTrustOptions = {}) {
		return trustedEntity("openid_wallet_provider", id, anchors, operationOptions(options));
	}
	static async createWalletAttestation(
		id: string,
		params: CreateWalletAttestationParams,
		signer: JwtSigner,
		options: WalletTrustOptions = {},
	): Promise<Result<string>> {
		const evidence = await signingEvidence(id, options);
		return evidence.ok ? createAttestation(id, params, signer, options) : evidence;
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

export interface DiscoveredCredentialIssuer extends TrustedWalletEntity {
	readonly authorizationServers: readonly TrustedWalletEntity[];
}

export class CredentialIssuerRole extends AttestationConsumer {
	readonly type = "openid_credential_issuer";
	static parseMetadata(metadata: unknown) {
		return roleSchemas.openid_credential_issuer.safeParse(metadata);
	}
	static async discover(
		id: string,
		anchors: TrustAnchorSet,
		options: WalletTrustOptions = {},
	): Promise<Result<DiscoveredCredentialIssuer>> {
		const scoped = operationOptions(options);
		const issuer = await trustedEntity("openid_credential_issuer", id, anchors, scoped);
		if (!issuer.ok) return issuer;
		const servers = (issuer.value.metadata.authorization_servers ?? [id]) as string[];
		const authorizationServers: TrustedWalletEntity[] = [];
		for (const server of servers) {
			const { trustChain: _, ...nestedOptions } = scoped;
			const paths =
				server === id
					? ok([options.trustChain ?? options.entityChains?.get(id)])
					: await candidates(server, anchors, nestedOptions);
			if (!paths.ok) return paths;
			let found: TrustedWalletEntity | undefined;
			if (server === id) {
				const metadata = issuer.value.trustChain.resolvedMetadata.oauth_authorization_server;
				if (metadata?.issuer === server)
					found = { entityId: server, metadata, trustChain: issuer.value.trustChain };
			} else {
				for (const path of paths.value) {
					if (!path) continue;
					const checked = await validateTrustChain(path, anchors, scoped);
					const metadata = checked.valid
						? checked.chain.resolvedMetadata.oauth_authorization_server
						: undefined;
					if (checked.valid && checked.chain.entityId === server && metadata?.issuer === server) {
						found = { entityId: server, metadata, trustChain: checked.chain };
						break;
					}
				}
			}
			if (!found) return failure("Authorization server lacks valid federation metadata");
			authorizationServers.push(found);
		}
		return ok({ ...issuer.value, authorizationServers });
	}
	discover(id: string, options: WalletTrustOptions = {}) {
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
	static discover(id: string, anchors: TrustAnchorSet, options: WalletTrustOptions = {}) {
		return trustedEntity("openid_credential_verifier", id, anchors, operationOptions(options));
	}
	static prepareAuthorizationRequest(
		outer: WalletAuthorizationRequest,
		anchors: TrustAnchorSet,
		options: AuthorizationRequestOptions = {},
	): Promise<Result<PreparedAuthorizationRequest>> {
		return prepareRequest(outer, anchors, operationOptions(options) as AuthorizationRequestOptions);
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
		options: AuthorizationRequestOptions = {},
	) {
		try {
			entityId(id);
		} catch {
			return failure("Invalid signing entity identifier");
		}
		return createRequest(id, request, signer, options);
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
		const scoped = operationOptions(options);
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
		options: AuthorizationRequestOptions = {},
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
