/**
 * @oidfed/crypto — base64url codec (RFC 4648 §5, unpadded).
 *
 * Canonical unpadded encoding shared by the package's JWS and JWK helpers.
 */

import { CryptoError } from "./types.js";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const REVERSE = new Map<string, number>([...ALPHABET].map((char, index) => [char, index]));

/** Encode bytes as canonical, unpadded base64url without host encoding APIs.
 * @throws {CryptoError} MALFORMED_JWS if the input is not a Uint8Array.
 */
export function encodeBase64url(bytes: Uint8Array): string {
	if (!(bytes instanceof Uint8Array)) throw new CryptoError("MALFORMED_JWS", "Expected bytes");
	let output = "";
	for (let index = 0; index < bytes.length; index += 3) {
		const chunk =
			((bytes[index] ?? 0) << 16) | ((bytes[index + 1] ?? 0) << 8) | (bytes[index + 2] ?? 0);
		output += ALPHABET[(chunk >>> 18) & 63];
		output += ALPHABET[(chunk >>> 12) & 63];
		if (index + 1 < bytes.length) output += ALPHABET[(chunk >>> 6) & 63];
		if (index + 2 < bytes.length) output += ALPHABET[chunk & 63];
	}
	return output;
}

/**
 * Strict decoder: base64url alphabet only, no padding, no whitespace, and the
 * canonical-length check RFC 7515 §C requires (a trailing chunk of length 1
 * is impossible; non-zero trailing bits are rejected).
 * @throws {CryptoError} MALFORMED_JWS for invalid or noncanonical input.
 */
export function decodeBase64url(value: string): Uint8Array {
	if (typeof value !== "string")
		throw new CryptoError("MALFORMED_JWS", "Expected a base64url string");
	if (value.length % 4 === 1) {
		throw new CryptoError("MALFORMED_JWS", "base64url value has impossible length");
	}
	const bytes = new Uint8Array(Math.floor((value.length * 6) / 8));
	let buffer = 0;
	let bits = 0;
	let offset = 0;
	for (const character of value) {
		const sextet = REVERSE.get(character);
		if (sextet === undefined) {
			throw new CryptoError("MALFORMED_JWS", "base64url value contains an invalid character");
		}
		buffer = (buffer << 6) | sextet;
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			bytes[offset++] = (buffer >>> bits) & 255;
		}
	}
	if (bits > 0 && (buffer & ((1 << bits) - 1)) !== 0) {
		throw new CryptoError("MALFORMED_JWS", "base64url value has non-zero trailing bits");
	}
	return bytes;
}

/** Encode a string as UTF-8. Lone UTF-16 surrogates become U+FFFD, as in TextEncoder.
 * @returns Fresh bytes; no host codecs or polyfills are needed.
 * @throws {CryptoError} MALFORMED_JWS if the input is not a string.
 */
export function utf8Encode(value: string): Uint8Array {
	if (typeof value !== "string") throw new CryptoError("MALFORMED_JWS", "Expected a string");
	const bytes = new Uint8Array(value.length * 3);
	let offset = 0;
	for (let index = 0; index < value.length; index++) {
		let point = value.charCodeAt(index);
		if (point >= 0xd800 && point <= 0xdbff) {
			const next = value.charCodeAt(index + 1);
			if (next >= 0xdc00 && next <= 0xdfff) {
				point = 0x10000 + ((point - 0xd800) << 10) + next - 0xdc00;
				index++;
			} else point = 0xfffd;
		} else if (point >= 0xdc00 && point <= 0xdfff) point = 0xfffd;
		if (point < 0x80) bytes[offset++] = point;
		else if (point < 0x800) {
			bytes[offset++] = 0xc0 | (point >> 6);
			bytes[offset++] = 0x80 | (point & 0x3f);
		} else if (point < 0x10000) {
			bytes[offset++] = 0xe0 | (point >> 12);
			bytes[offset++] = 0x80 | ((point >> 6) & 0x3f);
			bytes[offset++] = 0x80 | (point & 0x3f);
		} else {
			bytes[offset++] = 0xf0 | (point >> 18);
			bytes[offset++] = 0x80 | ((point >> 12) & 0x3f);
			bytes[offset++] = 0x80 | ((point >> 6) & 0x3f);
			bytes[offset++] = 0x80 | (point & 0x3f);
		}
	}
	return bytes.slice(0, offset);
}

/** Decode UTF-8, omitting one leading BOM. Malformed sequences reject by default.
 * Set fatal:false for ordinary text bodies that use replacement decoding.
 * @throws {CryptoError} MALFORMED_JWS for invalid bytes in fatal mode or the wrong input type.
 */
export function utf8Decode(bytes: Uint8Array, options: { readonly fatal?: boolean } = {}): string {
	if (!(bytes instanceof Uint8Array)) throw new CryptoError("MALFORMED_JWS", "Expected bytes");
	let output = "";
	let needed = 0;
	let seen = 0;
	let point = 0;
	let lower = 0x80;
	let upper = 0xbf;
	let first = true;
	const emit = (value: number) => {
		if (!first || value !== 0xfeff) output += String.fromCodePoint(value);
		first = false;
	};
	const invalid = () => {
		if (options.fatal !== false)
			throw new CryptoError("MALFORMED_JWS", "Invalid or truncated UTF-8 sequence");
		emit(0xfffd);
	};
	for (let index = 0; index < bytes.length; index++) {
		const byte = bytes[index] as number;
		if (needed === 0) {
			if (byte <= 0x7f) emit(byte);
			else if (byte >= 0xc2 && byte <= 0xdf) {
				needed = 1;
				point = byte & 0x1f;
			} else if (byte >= 0xe0 && byte <= 0xef) {
				needed = 2;
				point = byte & 0x0f;
				if (byte === 0xe0) lower = 0xa0;
				if (byte === 0xed) upper = 0x9f;
			} else if (byte >= 0xf0 && byte <= 0xf4) {
				needed = 3;
				point = byte & 7;
				if (byte === 0xf0) lower = 0x90;
				if (byte === 0xf4) upper = 0x8f;
			} else invalid();
			continue;
		}
		if (byte < lower || byte > upper) {
			needed = 0;
			seen = 0;
			point = 0;
			lower = 0x80;
			upper = 0xbf;
			invalid();
			index--;
			continue;
		}
		lower = 0x80;
		upper = 0xbf;
		point = (point << 6) | (byte & 0x3f);
		if (++seen === needed) {
			emit(point);
			needed = 0;
			seen = 0;
			point = 0;
		}
	}
	if (needed !== 0) invalid();
	return output;
}
