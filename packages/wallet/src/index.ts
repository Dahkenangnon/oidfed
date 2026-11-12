export type {
	AuthenticateWalletOptions,
	CreateWalletAttestationParams,
	VerifiedWalletAttestation,
	WalletAttestation,
	WalletAttestationVerificationOptions,
} from "./attestation.js";
export { parseConcatenatedWalletAttestation } from "./attestation.js";
export type {
	CredentialIssuerMetadata,
	CredentialIssuerPublicationMetadata,
	CredentialVerifierMetadata,
	CredentialVerifierPublicationMetadata,
	DcqlQuery,
	WalletProviderMetadata,
	WalletProviderPublicationMetadata,
} from "./metadata.js";
export type {
	AuthorizationRequestContext,
	AuthorizationRequestCreationOptions,
	AuthorizationRequestOptions,
	PreparedAuthorizationRequest,
	ValidatedWalletRequest,
	WalletAuthorizationRequest,
} from "./request.js";
export type {
	AttestationVerificationOptions,
	CredentialIssuerDiscoveryOptions,
	CredentialVerificationOptions,
	DiscoveredCredentialIssuer,
	WalletRoleConfig,
} from "./roles.js";
export { CredentialIssuerRole, CredentialVerifierRole, WalletProviderRole } from "./roles.js";
export type { TrustedWalletEntity, WalletTrustOptions } from "./trust.js";
