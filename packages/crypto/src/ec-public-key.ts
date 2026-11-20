/** SEC 1 public-point validation for the three NIST curves used by JWS.
 * Some Web Crypto implementations accept off-curve coordinates during import.
 * This checks public data only; signing and signature verification stay in the backend.
 */
import { decodeBase64url } from "./encoding.js";
import { CryptoError, type Jwk } from "./types.js";

const CURVES = {
	"P-256": {
		p: (1n << 256n) - (1n << 224n) + (1n << 192n) + (1n << 96n) - 1n,
		b: 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn,
	},
	"P-384": {
		p: (1n << 384n) - (1n << 128n) - (1n << 96n) + (1n << 32n) - 1n,
		b: 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aefn,
	},
	"P-521": {
		p: (1n << 521n) - 1n,
		b: 0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00n,
	},
} as const;

function coordinate(value: string): bigint {
	let result = 0n;
	for (const byte of decodeBase64url(value)) result = (result << 8n) | BigInt(byte);
	return result;
}

/** Check an already structurally validated EC JWK; other key types are unchanged. */
export function assertEcPublicPoint(key: Jwk): void {
	if (key.kty !== "EC") return;
	const curve = CURVES[key.crv as keyof typeof CURVES];
	if (!curve || typeof key.x !== "string" || typeof key.y !== "string")
		throw new CryptoError("MALFORMED_KEY", "Unsupported EC public point");
	const x = coordinate(key.x),
		y = coordinate(key.y),
		{ p, b } = curve;
	const rhs = (((((x * x) % p) * x - 3n * x + b) % p) + p) % p;
	if (x >= p || y >= p || (y * y) % p !== rhs)
		throw new CryptoError("MALFORMED_KEY", "EC public point is outside its curve");
}
