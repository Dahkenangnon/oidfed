/** A replay-protected JWT identifier scoped to its issuer and audience. */
export interface JtiReplayClaim {
	readonly issuer: string;
	readonly audience: string;
	readonly jti: string;
	/** JWT expiration as a NumericDate. */
	readonly expiresAt: number;
}

/** Atomic replay protection for one-time JWT processing. */
export interface ReplayStore {
	/** Returns true when claimed, or false when the claim was already used. */
	useJti(claim: JtiReplayClaim): Promise<boolean>;
}
