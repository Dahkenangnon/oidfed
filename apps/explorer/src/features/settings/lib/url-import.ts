/**
 * URL-based settings import.
 *
 * The Settings page reads a `?import=<url>` query parameter; this module
 * provides the read-only primitives needed to (a) fetch and validate the
 * remote JSON and (b) compute how it would combine with the current
 * settings, leaving the actual apply step to the caller.
 *
 * Two combination modes are supported:
 *
 *   - **merge** (default for URL imports): take the union of trust anchors
 *     and leave all other settings (theme, timeouts, etc.) untouched. This is
 *     the friendly-default form, because a URL invitation from a demo
 *     federation should not overwrite the visitor's personal preferences.
 *
 *   - **replace**: full overwrite, identical semantics to the existing
 *     file-picker import path. Useful when the visitor explicitly wants the
 *     incoming snapshot to win.
 *
 * Imports never auto-apply — the page always presents a preview first.
 */

import type { Settings } from "@/lib/settings";
import { SettingsSchema } from "@/lib/settings";

export interface FetchedSettings {
	readonly settings: Settings;
	readonly source: string;
}

export type FetchResult =
	| { readonly ok: true; readonly value: FetchedSettings }
	| { readonly ok: false; readonly error: FetchError };

export type FetchError =
	| { readonly kind: "invalid-url"; readonly message: string }
	| { readonly kind: "network"; readonly message: string }
	| { readonly kind: "http"; readonly status: number; readonly message: string }
	| { readonly kind: "not-json"; readonly message: string }
	| { readonly kind: "schema"; readonly message: string };

/**
 * Validate `?import=<value>` against a parsed URL with a known protocol.
 * Returns the normalised URL on success, an error describing the rejection
 * otherwise. We refuse anything that isn't http: or https: so a malicious
 * page can't trick the explorer into reading from data:, javascript:, file:,
 * or other schemes.
 */
export function validateImportUrl(
	raw: string,
): { readonly ok: true; readonly value: URL } | { readonly ok: false; readonly error: string } {
	let url: URL;
	try {
		url = new URL(raw);
	} catch {
		return { ok: false, error: "Import URL is not a well-formed URL" };
	}
	if (url.protocol !== "https:" && url.protocol !== "http:") {
		return {
			ok: false,
			error: `Import URL must use http:// or https:// (got ${url.protocol})`,
		};
	}
	return { ok: true, value: url };
}

/**
 * Fetch a settings JSON document from a URL, validate it against
 * `SettingsSchema`, and return either a ready-to-merge Settings object or
 * a structured error.
 *
 * The caller is responsible for showing a confirmation step — this function
 * never writes to localStorage, never calls `setSettings`.
 */
export async function fetchSettings(
	urlInput: string,
	options: { readonly timeoutMs?: number; readonly signal?: AbortSignal } = {},
): Promise<FetchResult> {
	const validated = validateImportUrl(urlInput);
	if (!validated.ok) {
		return { ok: false, error: { kind: "invalid-url", message: validated.error } };
	}

	const ctrl = new AbortController();
	const onAbort = () => ctrl.abort();
	if (options.signal) {
		if (options.signal.aborted) ctrl.abort();
		else options.signal.addEventListener("abort", onAbort, { once: true });
	}
	const timer = setTimeout(() => ctrl.abort(), options.timeoutMs ?? 10_000);

	try {
		let response: Response;
		try {
			response = await fetch(validated.value.toString(), {
				signal: ctrl.signal,
				headers: { Accept: "application/json" },
				redirect: "follow",
				credentials: "omit",
			});
		} catch (err: unknown) {
			const msg = err instanceof Error ? err.message : String(err);
			return {
				ok: false,
				error: {
					kind: "network",
					message:
						`Network error fetching settings — likely CORS. The host must serve ` +
						`Access-Control-Allow-Origin: * (or include explore.oidfed.com). (${msg})`,
				},
			};
		}

		if (!response.ok) {
			return {
				ok: false,
				error: {
					kind: "http",
					status: response.status,
					message: `Settings URL returned HTTP ${response.status} ${response.statusText}`,
				},
			};
		}

		let raw: unknown;
		try {
			raw = await response.json();
		} catch (err: unknown) {
			const msg = err instanceof Error ? err.message : String(err);
			return {
				ok: false,
				error: { kind: "not-json", message: `Response body was not valid JSON: ${msg}` },
			};
		}

		const parsed = SettingsSchema.safeParse(raw);
		if (!parsed.success) {
			return {
				ok: false,
				error: {
					kind: "schema",
					message: `Document does not match the settings schema: ${parsed.error.issues
						.map((i) => `${i.path.join(".") || "<root>"}: ${i.message}`)
						.join("; ")}`,
				},
			};
		}

		return { ok: true, value: { settings: parsed.data, source: validated.value.toString() } };
	} finally {
		clearTimeout(timer);
		if (options.signal) options.signal.removeEventListener("abort", onAbort);
	}
}

export interface AnchorDiff {
	readonly toAdd: ReadonlyArray<{ readonly entityId: string }>;
	readonly alreadyPresent: ReadonlyArray<{ readonly entityId: string }>;
}

/**
 * Classify each incoming trust anchor as new (not in current) or already
 * present. Drives the preview UI so the visitor can see exactly how the
 * import would affect their existing list.
 */
export function diffAnchors(
	current: Settings["trustAnchors"],
	incoming: Settings["trustAnchors"],
): AnchorDiff {
	const existing = new Set(current.map((a) => a.entityId));
	const toAdd: { entityId: string }[] = [];
	const alreadyPresent: { entityId: string }[] = [];
	for (const anchor of incoming) {
		if (existing.has(anchor.entityId)) {
			alreadyPresent.push({ entityId: anchor.entityId });
		} else {
			toAdd.push({ entityId: anchor.entityId });
		}
	}
	return { toAdd, alreadyPresent };
}

/**
 * Additive merge — union the trust anchor lists by entityId, keep every
 * other field on the current settings untouched. This is the default for
 * URL-based imports because such links arrive unsolicited (e.g. from a
 * demo federation page) and must not overwrite preferences the visitor
 * has already configured.
 */
export function mergeSettings(current: Settings, incoming: Settings): Settings {
	const { toAdd } = diffAnchors(current.trustAnchors, incoming.trustAnchors);
	return {
		...current,
		trustAnchors: [...current.trustAnchors, ...toAdd],
	};
}
