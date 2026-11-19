/** Shared operations using the host's crypto engine, with checked backend results. */
import { type CryptoEngine, CryptoError, utf8Encode } from "@oidfed/crypto";

/** Hash text using the supplied engine and return lowercase hexadecimal SHA-256. */
export async function sha256Hex(value: string, engine: CryptoEngine): Promise<string> {
	const digest = await engine.digest("SHA-256", utf8Encode(value));
	if (!(digest instanceof Uint8Array) || digest.length !== 32)
		throw new CryptoError("ENGINE_CONTRACT_VIOLATION", "SHA-256 must return 32 bytes");
	return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** Generate a UUID version 4 using the host's secure random generator. */
export async function randomUuid(engine: CryptoEngine): Promise<string> {
	const supplied = await engine.random(16);
	if (!(supplied instanceof Uint8Array) || supplied.length !== 16)
		throw new CryptoError("ENGINE_CONTRACT_VIOLATION", "UUID generation requires 16 random bytes");
	const bytes = new Uint8Array(supplied);
	bytes[6] = ((bytes[6] ?? 0) & 15) | 64;
	bytes[8] = ((bytes[8] ?? 0) & 63) | 128;
	const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
	return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
