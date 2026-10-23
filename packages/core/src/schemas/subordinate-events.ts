/** OpenID Federation Subordinate Events Endpoint, Draft 01. */
import { z } from "zod";
import { EntityIdSchema } from "./entity-id.js";

export const SubordinateEventType = {
	Registration: "registration",
	Revocation: "revocation",
	Suspension: "suspension",
	MetadataUpdate: "metadata_update",
	MetadataPolicyUpdate: "metadata_policy_update",
	JwksUpdate: "jwks_update",
} as const;

export const SubordinateEventSchema = z.looseObject({
	iat: z.number(),
	// Draft 01 §2.3.3 also permits operator-defined event names.
	event: z.string(),
	event_description: z.string().optional(),
	information_uri: z.url().optional(),
});

export const SubordinateEventsResponseSchema = z.looseObject({
	iss: EntityIdSchema,
	sub: EntityIdSchema,
	iat: z.number(),
	exp: z.number().optional(),
	federation_registration_events: z.array(SubordinateEventSchema),
});

export type SubordinateEvent = z.infer<typeof SubordinateEventSchema>;
export type SubordinateEventsResponse = z.infer<typeof SubordinateEventsResponseSchema>;
