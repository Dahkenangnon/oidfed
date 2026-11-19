export { type VerifiedClientAssertion, verifyClientAssertion } from "./client-auth.js";
export {
	isValidAlgorithm,
	JWK_PUBLIC_FIELDS,
	jwkThumbprint,
	selectVerificationKey,
	stripPrivateFields,
	timingSafeEqual,
} from "./keys.js";
export { type SignEntityStatementOptions, signEntityStatement } from "./sign.js";
export {
	assertTypHeader,
	decodeEntityConfiguration,
	decodeEntityStatement,
	decodeSubordinateStatement,
	type FederationJwsOptions,
	verifyEntityStatement,
} from "./verify.js";

export {
	type VerifiedProtocolJwt,
	type VerifyProtocolJwtOptions,
	verifyProtocolJwt,
} from "./verify-protocol.js";
