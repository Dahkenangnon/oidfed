/**
 * Opt-in helper that fetches a Trust Mark `logo_uri` and verifies its
 * Content-Type starts with `image/`. The spec requires `logo_uri` to point
 * to a "valid image file"; the schema layer can only check URL syntax, so
 * integrators that want to verify the publisher honoured the obligation use
 * this helper.
 *
 * The library's HTTP fetch infrastructure is https-only for SSRF protection.
 * Non-https logo URLs (which the spec permits) cannot be verified by this
 * helper and must be handled by integrator-side code.
 */
import { DEFAULT_HTTP_TIMEOUT_MS, FederationErrorCode } from "../constants.js";
import { err, type FederationError, federationError, ok, type Result } from "../errors.js";
import { validateFetchUrl } from "../trust-chain/fetch.js";
import type { FederationOptions } from "../types.js";

export interface ValidateTrustMarkLogoOptions extends FederationOptions {}

export async function validateTrustMarkLogo(
	url: string,
	options?: ValidateTrustMarkLogoOptions,
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
		const contentType = response.headers.get("content-type")?.split(";")[0]?.trim() ?? "";
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
