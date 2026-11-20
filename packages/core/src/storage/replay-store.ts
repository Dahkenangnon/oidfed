import type { z } from "zod";
import type { JtiReplayClaimSchema } from "./record-schemas.js";
/** Atomic replay-claim storage contracts for JWT authentication. */

/** A replay-protected JWT identifier scoped to its issuer and audience. */
export type JtiReplayClaim = Readonly<z.infer<typeof JtiReplayClaimSchema>>;

/** Atomic replay protection for one-time JWT processing. */
export interface ReplayStore {
	/** Returns true when claimed, or false when the claim was already used or has expired. */
	useJti(claim: JtiReplayClaim): Promise<boolean>;
}
