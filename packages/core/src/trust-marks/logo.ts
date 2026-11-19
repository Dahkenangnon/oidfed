/**
 * Optional HTTPS logo checks based on the response's image media type.
 * This does not decode image bytes or prove the resource is a valid image file.
 * The shared URL policy permits HTTPS retrieval only; the host handles other schemes.
 */

import { DEFAULT_HTTP_TIMEOUT_MS, FederationErrorCode } from "../constants.js";
import { err, type FederationError, federationError, ok, type Result } from "../errors.js";
import { parseContentTypeHeader } from "../http.js";
import { validateFetchUrl } from "../trust-chain/fetch.js";
import type { FederationOptions } from "../types.js";

export interface ValidateTrustMarkLogoOptions extends FederationOptions {}

/**
 * Fetch an HTTPS logo and check its image media type. This does not decode or validate image bytes.
 */
export async function validateTrustMarkLogo(
	url: string,
	options: ValidateTrustMarkLogoOptions,
): Promise<Result<{ contentType: string }, FederationError>> {
	if (url.includes("#")) {
		return err(
			federationError(
				FederationErrorCode.InvalidMetadata,
				`Helper does not fetch URLs with fragments: ${url}`,
			),
		);
	}

	const urlValidation = validateFetchUrl(url, options);
	if (!urlValidation.ok) {
		return err(
			federationError(FederationErrorCode.InvalidMetadata, urlValidation.error.description),
		);
	}

	const fetchFn = options?.httpClient ?? fetch;
	const timeoutMs = options?.httpTimeoutMs ?? DEFAULT_HTTP_TIMEOUT_MS;
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), timeoutMs);

	try {
		const response = await fetchFn(url, {
			method: "GET",
			headers: { Accept: "image/*" },
			signal: controller.signal,
		});
		clearTimeout(timer);
		if (!response.ok) {
			return err(
				federationError(
					FederationErrorCode.InvalidMetadata,
					`HTTP ${response.status} fetching logo_uri: ${url}`,
				),
			);
		}
		const contentType =
			parseContentTypeHeader(response.headers.get("content-type"))?.mediaType ?? "";
		if (!contentType.toLowerCase().startsWith("image/")) {
			return err(
				federationError(
					FederationErrorCode.InvalidMetadata,
					`logo_uri response Content-Type is not an image: '${contentType}'`,
				),
			);
		}
		return ok({ contentType });
	} catch (cause) {
		clearTimeout(timer);
		return err(
			federationError(
				FederationErrorCode.InvalidMetadata,
				cause instanceof Error ? cause.message : `Network error fetching logo_uri: ${url}`,
				cause,
			),
		);
	}
}
