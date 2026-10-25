export type {
	AuthenticateWalletOptions,
	CreateWalletAttestationParams,
	VerifiedWalletAttestation,
	WalletAttestation,
} from "./attestation.js";
export type {
	CredentialIssuerMetadata,
	CredentialVerifierMetadata,
	DcqlQuery,
	WalletProviderMetadata,
} from "./metadata.js";
export type {
	AuthorizationRequestContext,
	AuthorizationRequestOptions,
	PreparedAuthorizationRequest,
	ValidatedWalletRequest,
	WalletAuthorizationRequest,
} from "./request.js";
export type {
	AttestationVerificationOptions,
	CredentialVerificationOptions,
	DiscoveredCredentialIssuer,
	WalletRoleConfig,
} from "./roles.js";
export { CredentialIssuerRole, CredentialVerifierRole, WalletProviderRole } from "./roles.js";
export type { TrustedWalletEntity, WalletTrustOptions } from "./trust.js";
