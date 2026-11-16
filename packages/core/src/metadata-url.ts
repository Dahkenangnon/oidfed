/** HTTPS metadata endpoint URLs, without transport-specific address restrictions. */

import { err, type FederationError, federationError, ok, type Result } from "./errors.js";

/** Preserve caller-specific errors while applying the shared HTTPS and fragment rules. */
export function parseMetadataUrl(value: string, code: FederationError["code"]): Result<URL> {
	let parsed: URL;
	try {
		parsed = new URL(value);
	} catch {
		return err(federationError(code, `Invalid URL: ${value}`));
	}
	if (parsed.protocol !== "https:")
		return err(federationError(code, `URL must use https scheme: ${value}`));
	if (parsed.href.includes("#"))
		return err(federationError(code, `URL must not contain a fragment: ${value}`));
	return ok(parsed);
}
