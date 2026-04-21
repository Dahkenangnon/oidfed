/** Zod schema for OIDC Federation Entity Identifiers. */
import { z } from "zod";

/** Validates an HTTPS Entity Identifier with no credentials, query, or fragment. */
export const EntityIdSchema = z
	.url()
	.max(2048, "Entity ID must not exceed 2048 characters")
	.refine(
		(url) => {
			try {
				return new URL(url).protocol === "https:";
			} catch {
				return false;
			}
		},
		{ message: "Entity ID must use HTTPS" },
	)
	.refine(
		(url) => {
			try {
				const u = new URL(url);
				return !u.username && !u.password;
			} catch {
				return false;
			}
		},
		{ message: "Entity ID must not contain credentials" },
	)
	.refine(
		(url) => {
			try {
				const u = new URL(url);
				return !u.search && !u.hash;
			} catch {
				return false;
			}
		},
		{ message: "Entity ID must not contain query parameters or fragments" },
	)
	.brand<"EntityId">();
