/**
 * Interface for tracking JWT Token Identifiers (JTI) to prevent replay attacks.
 *
 * Implementations MUST atomically check-and-record: if the JTI has been seen
 * before, return `true`; otherwise record it and return `false`.
 */
export interface JtiStore {
	/**
	 * Check if a JTI has been seen before and record it if not.
	 *
	 * @param jti - The JWT Token Identifier to check
	 * @param expiresAt - The JWT expiration timestamp (Unix seconds). Implementations
	 *   SHOULD clean up entries after this time.
	 * @returns `true` if the JTI was already seen (replay), `false` if it's new
	 */
	hasSeenAndRecord(jti: string, expiresAt: number): Promise<boolean>;
}
