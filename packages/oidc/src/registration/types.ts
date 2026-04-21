import type { EntityId, FederationError, Result } from "@oidfed/core";

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
	/** All decoded JWT payload claims */
	readonly claims: Readonly<Record<string, unknown>>;
	/** Trust chain from JWT header (if present) */
	readonly trustChainHeader?: readonly string[];
}

/** Context for OP-side automatic registration processing */
export interface AutomaticRegistrationContext {
	/** The OP's own Entity Identifier */
	readonly opEntityId: EntityId;
	/** Maximum allowed clock skew in seconds (default: 60) */
	readonly clockSkewSeconds?: number;
}

export type ValidatedRequestObjectResult = Result<ValidatedRequestObject, FederationError>;
