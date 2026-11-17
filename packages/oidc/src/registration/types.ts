/** Authenticated Request Object and automatic registration context contracts. */

import type { Clock, EntityId, FederationError, Result } from "@oidfed/core";

/** Typed output of Request Object JWT validation. */
export interface ValidatedRequestObject {
	/** The RP's Entity Identifier (from `client_id` / `iss`) */
	readonly rpEntityId: EntityId;
	/** The OP's Entity Identifier (from `aud`) */
	readonly opEntityId: string;
	/** JWT expiration timestamp */
	readonly exp: number;
	/** Unique JWT identifier */
	readonly jti: string;
	/** Issued-at timestamp (if present) */
	readonly iat?: number;
	/** Protected typ accepted by the typing policy; omitted when the header is absent. */
	readonly headerTyp?: string;
	/** All decoded JWT payload claims */
	readonly claims: Readonly<Record<string, unknown>>;
	/** Trust chain from JWT header (if present) */
	readonly trustChainHeader?: readonly string[];
	/** Optional peer Trust Chain from the JWT header, describing the OP. */
	readonly peerTrustChainHeader?: readonly string[];
}

/** Context for OP-side automatic registration processing */
export interface AutomaticRegistrationContext {
	/** The OP's own Entity Identifier */
	readonly opEntityId: EntityId;
	/**
	 * strict requires an explicitly typed Request Object (default).
	 * compatible also permits generic JWT typing or an absent typ under RFC 9101 §10.8.
	 */
	readonly requestObjectTyping?: "strict" | "compatible";
	/** Maximum allowed clock skew in seconds (default: 60) */
	readonly clockSkewSeconds?: number;
	/** NumericDate clock used for expiry validation. */
	readonly clock?: Clock;
}

export type ValidatedRequestObjectResult = Result<ValidatedRequestObject, FederationError>;
