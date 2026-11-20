/** Structural validation for OpenID Federation Entity Identifiers. */

import { z } from "zod";
import { type EntityId, isValidEntityId } from "../types.js";

/** Validates an Entity Identifier and returns the exact string with the Core EntityId type. */
export const EntityIdSchema: z.ZodType<EntityId, string> = z
	.string()
	.refine(isValidEntityId, "Invalid Entity Identifier")
	.meta({ format: "uri", maxLength: 2048 });
