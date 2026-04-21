/**
 * Decode a single base64url-encoded JWT part (header or payload) into a parsed object.
 * Returns `null` if decoding or JSON parsing fails.
 */
export function decodeJwtPart(part: string): Record<string, unknown> | null {
	try {
		return JSON.parse(atob(part.replace(/-/g, "+").replace(/_/g, "/"))) as Record<string, unknown>;
	} catch {
		return null;
	}
}

/**
 * Extract the `federation_entity` metadata block from a decoded entity statement payload.
 * Returns an empty object if the metadata or `federation_entity` key is missing.
 */
export function extractFederationEntity(payload: Record<string, unknown>): Record<string, unknown> {
	const metadata = payload.metadata as Record<string, Record<string, unknown>> | undefined;
	return metadata?.federation_entity ?? {};
}
