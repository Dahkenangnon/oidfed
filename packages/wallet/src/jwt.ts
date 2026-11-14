export {
	checkApplicationJwtHeader as checkProtocolHeader,
	decodeApplicationJwt as decodeToken,
	matchesJwtType,
	signApplicationJwt as signToken,
	verifyApplicationJwt as verifyToken,
} from "@oidfed/core";
