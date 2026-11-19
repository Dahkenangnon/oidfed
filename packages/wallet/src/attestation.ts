import { cloneData } from "@oidfed/core";
import type { KeyringEntry } from "@oidfed/crypto";
/** Wallet profile binding of client attestation authentication to trusted Wallet Providers. */

import {
	type AuthenticateClientAttestationOptions,
	authenticateClientAttestation,
	type ClientAttestation,
	type ClientAttestationError,
	type ClientAttestationVerificationOptions,
	type CreateClientAttestationParams,
	createClientAttestation,
	ok,
	type Result,
	safeLogger,
	type TrustAnchorSet,
	verifyClientAttestation,
} from "@oidfed/core";
import {
	failure,
	protocolKeys,
	type TrustedWalletEntity,
	trustedEntity,
	type WalletTrustOptions,
} from "./trust.js";

export {
	invokeVerificationPolicy as invokePolicy,
	parseConcatenatedClientAttestation as parseConcatenatedWalletAttestation,
} from "@oidfed/core";
export type WalletAttestation = ClientAttestation;
export type CreateWalletAttestationParams = CreateClientAttestationParams;
export interface VerifiedWalletAttestation {
	readonly attestation: WalletAttestation;
	readonly provider: TrustedWalletEntity;
}
export interface WalletAttestationVerificationOptions extends WalletTrustOptions {
	readonly expectedAudience?: string;
	readonly allowedAttestationAlgorithms?: readonly string[];
}
export interface AuthenticateWalletOptions
	extends WalletTrustOptions,
		Omit<
			AuthenticateClientAttestationOptions,
			"getAttester" | "acceptClient" | keyof WalletTrustOptions
		> {
	readonly acceptWallet: (
		verified: VerifiedWalletAttestation,
		signal?: AbortSignal,
	) => boolean | Promise<boolean>;
}
/**
 * Create a JWT Wallet Attestation using the shared client-attestation signer. Issuance approval is
 * host policy.
 */
export function createAttestation(
	issuer: string,
	params: CreateWalletAttestationParams,
	signer: KeyringEntry,
	options: WalletTrustOptions,
): Promise<Result<string>> {
	return createClientAttestation(issuer, params, signer, options);
}
function providerTrust(anchors: TrustAnchorSet, options: WalletAttestationVerificationOptions) {
	let provider: TrustedWalletEntity | undefined;
	const getAttester: ClientAttestationVerificationOptions["getAttester"] = async (
		issuer,
		header,
		signal,
	) => {
		const resolved = await trustedEntity(
			"openid_wallet_provider",
			issuer,
			anchors,
			{ ...options, signal },
			header.trust_chain as readonly string[] | undefined,
		);
		if (!resolved.ok) return resolved;
		provider = resolved.value;
		const keys = await protocolKeys(provider, "openid_wallet_provider", { ...options, signal });
		return keys.ok ? ok({ jwks: keys.value, expiresAt: provider.trustChain.expiresAt }) : keys;
	};
	return { getAttester, provider: () => provider };
}
/**
 * Establish Wallet Provider trust and verify its JWT attestation. This does not verify holder proof
 * of possession.
 */
export async function verifyAttestation(
	jwt: string,
	anchors: TrustAnchorSet,
	options: WalletAttestationVerificationOptions,
): Promise<Result<VerifiedWalletAttestation, ClientAttestationError>> {
	const trust = providerTrust(anchors, options);
	const verified = await verifyClientAttestation(jwt, {
		...options,
		getAttester: trust.getAttester,
	});
	if (!verified.ok) return verified;
	const provider = trust.provider();
	return provider
		? ok({ attestation: verified.value.attestation, provider })
		: failure("Wallet Provider trust is required");
}
/**
 * Verify provider trust, the attestation, holder proof, replay policy, and the host's acceptWallet
 * decision.
 */
export async function authenticateWallet(
	attestation: string,
	proof: string,
	anchors: TrustAnchorSet,
	options: AuthenticateWalletOptions,
): Promise<Result<VerifiedWalletAttestation, ClientAttestationError>> {
	if (typeof options.acceptWallet !== "function" || (!options.replayStore && !options.replay)) {
		const logger = safeLogger(options.logger);
		if (typeof options.acceptWallet !== "function")
			logger?.warn("Provide acceptWallet to decide whether to accept the Wallet");
		if (!options.replayStore && !options.replay)
			logger?.warn("Provide a replayStore for Client Attestation PoP replay protection");
		return failure("Invalid wallet authentication configuration");
	}
	const trust = providerTrust(anchors, { ...options, expectedAudience: options.audience });
	const verified = await authenticateClientAttestation(attestation, proof, {
		...options,
		getAttester: trust.getAttester,
		acceptClient: (value, signal) => {
			const provider = trust.provider();
			return provider
				? options.acceptWallet(
						{ attestation: value.attestation, provider: cloneData(provider) },
						signal,
					)
				: false;
		},
	});
	if (!verified.ok) return verified;
	const provider = trust.provider();
	return provider
		? ok({ attestation: verified.value.attestation, provider })
		: failure("Wallet Provider trust is required");
}
