/**
 * @oidfed/crypto — ECDSA signature format conversion.
 *
 * JWS requires fixed-width R||S (RFC 7518 §3.4). Some signing backends
 * return ASN.1 DER instead; adapters can convert at their custody boundary.
 */

import { CryptoError, type JwsAlgorithm } from "./types.js";

const COMPONENT_BYTES: Partial<Record<JwsAlgorithm, number>> = {
	ES256: 32,
	ES384: 48,
	ES512: 66,
};

function componentLength(algorithm: JwsAlgorithm): number {
	const length = Object.hasOwn(COMPONENT_BYTES, algorithm) ? COMPONENT_BYTES[algorithm] : undefined;
	if (length === undefined) {
		throw new CryptoError("UNSUPPORTED_ALGORITHM", `${algorithm} is not an ECDSA JWS algorithm`);
	}
	return length;
}

/**
 * Convert an ASN.1 DER ECDSA-Sig-Value to the JWS R||S form.
 *
 * Strict: every length is bounds-checked, long-form lengths must be minimal,
 * integers must be non-empty with minimal leading-zero encoding, the SEQUENCE
 * length must equal its content, and the input must be fully consumed —
 * truncated or padded signatures are rejected, never silently converted.
 * @param der - DER signature bytes returned by the signing backend.
 * @param algorithm - ES256, ES384 or ES512, which determines the component width.
 * @throws {CryptoError} MALFORMED_JWS for invalid DER; UNSUPPORTED_ALGORITHM for a non-ECDSA algorithm.
 */
export function derToJws(der: Uint8Array, algorithm: JwsAlgorithm): Uint8Array {
	const length = componentLength(algorithm);
	let offset = 0;
	const malformed = (detail: string): never => {
		throw new CryptoError("MALFORMED_JWS", `malformed DER ECDSA signature: ${detail}`);
	};
	const readByte = (): number => {
		if (offset >= der.length) malformed("truncated");
		return der[offset++] as number;
	};
	const readLength = (): number => {
		const first = readByte();
		if (first < 0x80) return first;
		const sizeBytes = first & 0x7f;
		// A DER ECDSA signature never needs more than 2 length bytes.
		if (sizeBytes === 0 || sizeBytes > 2) malformed("unsupported length form");
		let size = 0;
		for (let index = 0; index < sizeBytes; index++) {
			const byte = readByte();
			if (index === 0 && byte === 0) malformed("non-minimal length encoding");
			size = (size << 8) | byte;
		}
		if (size < 0x80) malformed("non-minimal length encoding");
		return size;
	};
	if (readByte() !== 0x30) malformed("expected SEQUENCE");
	const sequenceLength = readLength();
	if (offset + sequenceLength !== der.length) malformed("SEQUENCE length mismatch");
	const output = new Uint8Array(length * 2);
	for (const half of [0, 1] as const) {
		if (readByte() !== 0x02) malformed("expected INTEGER");
		const size = readLength();
		if (size === 0 || offset + size > der.length) malformed("bad INTEGER length");
		let start = offset;
		let remaining = size;
		if (der[start] === 0) {
			// A single leading zero is only valid as a sign pad for a high bit.
			if (remaining === 1 || ((der[start + 1] ?? 0) & 0x80) === 0) {
				malformed("non-minimal INTEGER encoding");
			}
			start += 1;
			remaining -= 1;
		} else if (((der[start] ?? 0) & 0x80) !== 0) {
			malformed("negative INTEGER");
		}
		if (remaining > length) malformed("INTEGER exceeds curve size");
		output.set(der.subarray(start, start + remaining), half * length + (length - remaining));
		offset = start + remaining;
	}
	if (offset !== der.length) malformed("trailing bytes");
	return output;
}

/** Convert fixed-width JWS R || S bytes to ASN.1 DER for a backend that needs DER.
 * This checks representation, not the signature's mathematical validity.
 * @throws {CryptoError} MALFORMED_JWS for invalid width/zero components; UNSUPPORTED_ALGORITHM for a non-ECDSA algorithm.
 */
export function jwsToDer(signature: Uint8Array, algorithm: JwsAlgorithm): Uint8Array {
	const length = componentLength(algorithm);
	if (signature.length !== length * 2) {
		throw new CryptoError("MALFORMED_JWS", "ECDSA signature has the wrong length for its curve");
	}
	const encodeInteger = (component: Uint8Array): number[] => {
		if (component.every((byte) => byte === 0)) {
			throw new CryptoError("MALFORMED_JWS", "ECDSA components must be positive");
		}
		let start = 0;
		while (start < component.length - 1 && component[start] === 0) start += 1;
		const needsPad = ((component[start] ?? 0) & 0x80) !== 0;
		const body = [...(needsPad ? [0] : []), ...component.subarray(start)];
		return [0x02, body.length, ...body];
	};
	const r = encodeInteger(signature.subarray(0, length));
	const s = encodeInteger(signature.subarray(length));
	const content = [...r, ...s];
	const header =
		content.length < 0x80 ? [0x30, content.length] : [0x30, 0x81, content.length & 0xff];
	return new Uint8Array([...header, ...content]);
}
