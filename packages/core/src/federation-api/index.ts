/** Federation endpoint clients and signed response verification. */

export { type VerifySignedJwkSetOptions, verifySignedJwkSet } from "../jwks/signed-jwk-set.js";
export {
	buildExtendedListRequestParameters,
	fetchExtendedSubordinatesList,
} from "./extended-list.js";
export {
	type FetchTrustMarkListParams,
	fetchTrustMarkList,
} from "./fetch-trust-mark-list.js";
export {
	type FetchHistoricalKeysOptions,
	fetchHistoricalKeys,
	type SelectHistoricalVerificationKeyOptions,
	selectHistoricalVerificationKey,
	verifyHistoricalKeysResponse,
} from "./historical-keys.js";
export {
	fetchResolveResponse,
	type ResolveRequestParams,
	type VerifyResolveResponseOptions,
	verifyResolveResponse,
} from "./resolve.js";
export {
	fetchListSubordinates,
	fetchListSubordinatesForIssuer,
	type ListSubordinatesFilter,
} from "./subordinate-listing.js";
export {
	type VerifyTrustMarkStatusOptions,
	verifyTrustMarkStatusResponse,
} from "./trust-mark-status.js";
export { type VerifyOptions, validateExpectedIssuer } from "./verify-issuer.js";
