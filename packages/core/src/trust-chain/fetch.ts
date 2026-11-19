/** HTTP fetching for Entity Configurations and Subordinate Statements, with SSRF protection. */

import { ecCacheKey, esCacheKey } from "../cache/index.js";
import {
	DEFAULT_CACHE_TTL_SECONDS,
	DEFAULT_HTTP_TIMEOUT_MS,
	DEFAULT_MAX_RESPONSE_BYTES,
	FederationErrorCode,
	InternalErrorCode,
	MediaType,
	WELL_KNOWN_OPENID_FEDERATION,
} from "../constants.js";
import { fetchFederationEndpoint } from "../endpoint-client.js";
import { err, type FederationError, ok, type Result } from "../errors.js";
import { isExactContentType, parseContentTypeHeader } from "../http.js";
import { readResponseBody } from "../http-response.js";
import { decodeEntityStatement } from "../jose/verify.js";
import { safeLogger } from "./../logging.js";
import {
	type EntityId,
	entityId,
	type FederationOptions,
	isValidEntityId,
	nowSeconds,
} from "../types.js";
import { fetchFailure, httpFailureStatus } from "./fetch-failure.js";

// --- IANA Special-Use IP Detection ---

/** Full IANA IPv4 Special-Purpose Address Registry (16 entries).
 * https://www.iana.org/assignments/iana-ipv4-special-registry/ */
const SPECIAL_USE_IPV4_TABLE: { prefix: number; mask: number }[] = [
	{ prefix: 0x00000000, mask: 0xff000000 }, // 0.0.0.0/8
	{ prefix: 0x0a000000, mask: 0xff000000 }, // 10.0.0.0/8 (Private)
	{ prefix: 0x64400000, mask: 0xffc00000 }, // 100.64.0.0/10 (Shared Address Space)
	{ prefix: 0x7f000000, mask: 0xff000000 }, // 127.0.0.0/8 (Loopback)
	{ prefix: 0xa9fe0000, mask: 0xffff0000 }, // 169.254.0.0/16 (Link-local)
	{ prefix: 0xac100000, mask: 0xfff00000 }, // 172.16.0.0/12 (Private)
	{ prefix: 0xc0000000, mask: 0xffffff00 }, // 192.0.0.0/24 (IETF Protocol Assignments)
	{ prefix: 0xc0000200, mask: 0xffffff00 }, // 192.0.2.0/24 (TEST-NET-1)
	{ prefix: 0xc0586300, mask: 0xffffff00 }, // 192.88.99.0/24 (6to4 Relay Anycast)
	{ prefix: 0xc0a80000, mask: 0xffff0000 }, // 192.168.0.0/16 (Private)
	{ prefix: 0xc6120000, mask: 0xfffe0000 }, // 198.18.0.0/15 (Benchmarking)
	{ prefix: 0xc6336400, mask: 0xffffff00 }, // 198.51.100.0/24 (TEST-NET-2)
	{ prefix: 0xcb007100, mask: 0xffffff00 }, // 203.0.113.0/24 (TEST-NET-3)
	{ prefix: 0xe0000000, mask: 0xf0000000 }, // 224.0.0.0/4 (Multicast)
	{ prefix: 0xf0000000, mask: 0xf0000000 }, // 240.0.0.0/4 (Reserved)
	{ prefix: 0xffffffff, mask: 0xffffffff }, // 255.255.255.255/32 (Limited Broadcast)
];

/** Convert IPv4 dotted-decimal string to unsigned 32-bit integer, or -1 on failure.
 * Uses a single-pass char-walk to avoid intermediate array allocation. */
export function ipv4ToInt(ip: string): number {
	let result = 0;
	let octet = 0;
	let dots = 0;
	for (let i = 0; i <= ip.length; i++) {
		const ch = ip.charCodeAt(i); // NaN at i === ip.length → treated as separator
		if (i === ip.length || ch === 46 /* '.' */) {
			if (dots > 3 || octet > 255) return -1;
			result = (result * 256 + octet) >>> 0;
			octet = 0;
			dots++;
		} else if (ch >= 48 /* '0' */ && ch <= 57 /* '9' */) {
			octet = octet * 10 + (ch - 48);
		} else {
			return -1; // non-digit, non-dot
		}
	}
	if (dots !== 4) return -1;
	return result;
}

/** Returns true if the given IPv4 address string is in any IANA special-use range. */
export function isSpecialUseIPv4(address: string): boolean {
	const ip = ipv4ToInt(address);
	if (ip < 0) return false;
	for (const { prefix, mask } of SPECIAL_USE_IPV4_TABLE) {
		if ((ip & mask) >>> 0 === prefix) return true;
	}
	return false;
}

/**
 * Expand an IPv6 address to its full 32-character lowercase hex form (no colons).
 * Handles `::` shorthand and IPv4-mapped notation (e.g. `::ffff:192.168.1.1`).
 * Returns empty string on parse error.
 */
export function expandIPv6(address: string): string {
	let addr = address;

	// Handle IPv4-mapped / IPv4-compatible notation (e.g. ::ffff:192.168.1.1)
	const dottedMatch = addr.match(/^(.*:)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
	if (dottedMatch) {
		const ipv4Int = ipv4ToInt(dottedMatch[2] as string);
		if (ipv4Int < 0) return "";
		const hi = ((ipv4Int >>> 16) & 0xffff).toString(16).padStart(4, "0");
		const lo = (ipv4Int & 0xffff).toString(16).padStart(4, "0");
		addr = `${dottedMatch[1]}${hi}:${lo}`;
	}

	const halves = addr.split("::");
	let groups: string[];
	if (halves.length === 2) {
		const left = halves[0] ? halves[0].split(":") : [];
		const right = halves[1] ? halves[1].split(":") : [];
		const missing = 8 - left.length - right.length;
		if (missing < 0) return "";
		groups = [...left, ...Array<string>(missing).fill("0"), ...right];
	} else if (halves.length === 1) {
		groups = addr.split(":");
	} else {
		return ""; // more than one "::" is invalid
	}
	if (groups.length !== 8) return "";
	return groups
		.map((g) => g.padStart(4, "0"))
		.join("")
		.toLowerCase();
}

/**
 * Returns true if the given IPv6 address string is in any IANA special-use range.
 * https://www.iana.org/assignments/iana-ipv6-special-registry/
 */
export function isSpecialUseIPv6(address: string): boolean {
	const hex = expandIPv6(address);
	if (!hex) return false;

	// ::/128: Unspecified Address
	if (hex === "00000000000000000000000000000000") return true;
	// ::1/128: Loopback Address
	if (hex === "00000000000000000000000000000001") return true;
	// ::ffff:0:0/96: IPv4-mapped Address
	if (hex.startsWith("00000000000000000000ffff")) return true;
	// 64:ff9b::/96: IPv4/IPv6 translation
	if (hex.startsWith("0064ff9b0000000000000000")) return true;
	// 64:ff9b:1::/48: IPv4/IPv6 translation
	if (hex.startsWith("0064ff9b0001")) return true;
	// 100::/64: Discard-only Address Block
	if (hex.startsWith("0100000000000000")) return true;
	// 2001::/23: IETF Protocol Assignments (second group 0x0000–0x01ff).
	// Two nibble-aligned 24-bit prefixes exactly cover the /23 range:
	//   "200100" → 2001:0000:: to 2001:00ff:: (incl. Teredo, ORCHIDv2 2001:0020::)
	//   "200101" → 2001:0100:: to 2001:01ff:: (incl. Drone Remote ID 2001:0130::)
	if (hex.startsWith("200100") || hex.startsWith("200101")) return true;
	// 2001:db8::/32: Documentation (separate from the /23 range above)
	if (hex.startsWith("20010db8")) return true;
	// 2002::/16: 6to4
	if (hex.startsWith("2002")) return true;
	// 2620:4f:8000::/48: Direct Delegation AS112 Service
	if (hex.startsWith("2620004f8000")) return true;
	// fc00::/7: Unique-Local Address (covers fc::/8 and fd::/8)
	const firstByte = Number.parseInt(hex.slice(0, 2), 16);
	if ((firstByte & 0xfe) === 0xfc) return true;
	// fe80::/10: Link-local Unicast
	const firstTwoBytes = Number.parseInt(hex.slice(0, 4), 16);
	if ((firstTwoBytes & 0xffc0) === 0xfe80) return true;
	// ff00::/8: Multicast
	if (hex.startsWith("ff")) return true;

	return false;
}

/**
 * Returns true if the address (IPv4 or IPv6) is in any IANA special-use range.
 * IPv6 literals from URL hostnames may arrive bracketed as `[::1]`.
 */
export function isSpecialUseIP(address: string): boolean {
	if (address.startsWith("[") && address.endsWith("]")) {
		return isSpecialUseIPv6(address.slice(1, -1));
	}
	return address.includes(":") ? isSpecialUseIPv6(address) : isSpecialUseIPv4(address);
}

// --- User-supplied CIDR additive check (IPv4 only) ---

function parseCIDR(cidr: string): { network: number; mask: number } | null {
	const [ip, prefix] = cidr.split("/");
	if (!ip || prefix === undefined) return null;
	const network = ipv4ToInt(ip);
	if (network < 0) return null;
	const bits = Number(prefix);
	if (Number.isNaN(bits) || bits < 0 || bits > 32) return null;
	const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
	return { network: (network & mask) >>> 0, mask };
}

function isBlockedCIDR(hostname: string, cidrs: string[]): boolean {
	const ip = ipv4ToInt(hostname);
	if (ip < 0) return false;
	for (const cidr of cidrs) {
		const parsed = parseCIDR(cidr);
		if (!parsed) continue;
		if ((ip & parsed.mask) >>> 0 === parsed.network) return true;
	}
	return false;
}

/** Validate a URL for safe federation fetching (HTTPS, no credentials, SSRF protection). */
export function validateFetchUrl(
	url: string,
	options?: Pick<FederationOptions, "blockedCIDRs" | "allowedHosts">,
): Result<URL, FederationError> {
	if (url.length > 2048) {
		return err({
			code: InternalErrorCode.Network,
			description: `URL exceeds maximum length of 2048 characters`,
		});
	}

	let parsed: URL;
	try {
		parsed = new URL(url);
	} catch {
		return err({
			code: InternalErrorCode.Network,
			description: `Invalid URL: ${url}`,
		});
	}

	if (parsed.protocol !== "https:") {
		return err({
			code: InternalErrorCode.Network,
			description: `URL must use HTTPS: ${url}`,
		});
	}

	if (parsed.username || parsed.password) {
		return err({
			code: InternalErrorCode.Network,
			description: `URL must not contain credentials: ${url}`,
		});
	}

	if (options?.allowedHosts) {
		if (!options.allowedHosts.includes(parsed.hostname)) {
			return err({
				code: InternalErrorCode.Network,
				description: `Host '${parsed.hostname}' is not in allowed hosts list`,
			});
		}
	}

	// Always check IANA special-use (covers IPv4 + IPv6 literals)
	if (isSpecialUseIP(parsed.hostname)) {
		return err({
			code: InternalErrorCode.Network,
			description: `Host '${parsed.hostname}' is a special-use address`,
		});
	}

	// User-supplied additional blocked CIDRs (additive, IPv4 only)
	if (options?.blockedCIDRs && isBlockedCIDR(parsed.hostname, options.blockedCIDRs)) {
		return err({
			code: InternalErrorCode.Network,
			description: `Host '${parsed.hostname}' is in blocked CIDR range`,
		});
	}

	return ok(parsed);
}

/** Validate Entity Identifier syntax without normalizing the identifier used in comparisons. */
export function validateEntityId(value: string): Result<EntityId, FederationError> {
	if (isValidEntityId(value)) {
		return ok(entityId(value));
	}
	return err({
		code: InternalErrorCode.Network,
		description: `Invalid entity ID: ${value}`,
	});
}

export interface PerformFetchOptions extends FederationOptions {
	headers?: RequestInit["headers"];
	/** Matching override. JSON accepts parameters; Federation registered media types default to none. */
	contentTypePolicy?: "exact" | "media-type";
	/** Accept header to send. Defaults to application/entity-statement+jwt. */
	accept?: string;
	/**
	 * Content-Type the response is required to carry. Defaults to the value of `accept`.
	 * Pass `null` to skip Content-Type validation entirely (e.g. when the verifier downstream
	 * inspects the response body header itself).
	 */
	expectedContentType?: string | null;
	method?: "GET" | "POST";
	/** Explicit request redirect policy; omitted callers keep Fetch's default. */
	redirect?: RequestInit["redirect"];
	/** Form-encoded body for authenticated federation endpoint requests. */
	body?: URLSearchParams;
	expectedStatus?: number;
	/** Decode Federation JSON error responses when enabled. */
	federationErrors?: boolean | readonly number[];
}

/**
 * Run a bounded HTTP request with configured URL, status, and response checks.
 * Transport failures are returned as federation errors; this does not authenticate a JWT body.
 */
export async function performFetch(
	url: string,
	options: PerformFetchOptions,
): Promise<Result<string, FederationError>> {
	if (options?.offline) {
		safeLogger(options.logger)?.warn(
			"Supply the missing federation evidence or protocol keys for offline trust evaluation",
		);
		return err({
			code: InternalErrorCode.Network,
			description: "Offline operation cannot access the network",
		});
	}
	const urlValidation = validateFetchUrl(url, options);
	if (!urlValidation.ok) return urlValidation;

	const fetchFn = options?.httpClient ?? fetch;
	const timeoutMs = options?.httpTimeoutMs ?? DEFAULT_HTTP_TIMEOUT_MS;
	const accept = options?.accept ?? MediaType.EntityStatement;
	const expectedContentType =
		options?.expectedContentType !== undefined ? options.expectedContentType : accept;
	const matchesContentType = (actual: string | null, expected: string) =>
		(options?.contentTypePolicy ??
			(expected.toLowerCase() === MediaType.Json ? "media-type" : "exact")) === "media-type"
			? parseContentTypeHeader(actual)?.mediaType.toLowerCase() === expected.toLowerCase()
			: isExactContentType(actual, expected);

	const controller = new AbortController();
	let timedOut = false;
	let receivedResponse = false;
	const timer = setTimeout(() => {
		timedOut = true;
		controller.abort();
	}, timeoutMs);

	const onAbort = () => controller.abort();
	options?.signal?.addEventListener("abort", onAbort, { once: true });
	if (options?.signal?.aborted) controller.abort();

	try {
		if (controller.signal.aborted) throw new DOMException("Request aborted", "AbortError");
		const response = await fetchFn(url, {
			signal: controller.signal,
			...(options?.redirect !== undefined ? { redirect: options.redirect } : {}),
			method: options?.method ?? "GET",
			...(options?.body ? { body: options.body.toString() } : {}),
			headers: {
				...Object.fromEntries(new Headers(options?.headers).entries()),
				Accept: accept,
				...(options?.body ? { "Content-Type": "application/x-www-form-urlencoded" } : {}),
			},
		});
		receivedResponse = true;

		if (
			!response.ok ||
			(options?.expectedStatus !== undefined && response.status !== options.expectedStatus)
		) {
			if (
				(options?.federationErrors === true ||
					(Array.isArray(options?.federationErrors) &&
						options.federationErrors.includes(response.status))) &&
				!response.ok &&
				matchesContentType(response.headers.get("content-type"), MediaType.Json)
			) {
				const body = await readResponseBody(
					response,
					options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES,
					controller.signal,
				);
				try {
					const parsed = JSON.parse(body) as { error?: unknown; error_description?: unknown };
					if (
						typeof parsed?.error === "string" &&
						/^[\x20-\x21\x23-\x5B\x5D-\x7E]+$/.test(parsed.error)
					) {
						return err(
							fetchFailure(
								{
									code: Object.values(FederationErrorCode).includes(
										parsed.error as FederationErrorCode,
									)
										? (parsed.error as FederationErrorCode)
										: InternalErrorCode.RemoteResponse,
									...(!Object.values(FederationErrorCode).includes(
										parsed.error as FederationErrorCode,
									)
										? { remoteError: { code: parsed.error, status: response.status } }
										: {}),
									description:
										typeof parsed.error_description === "string"
											? parsed.error_description
											: `HTTP ${response.status} from ${url}`,
								},
								{ kind: "http", status: response.status },
							),
						);
					}
				} catch {
					/* Fall back to the HTTP error for malformed JSON. */
				}
			} else {
				void response.body?.cancel().catch(() => {});
			}
			return err(
				fetchFailure(
					{
						code: InternalErrorCode.Network,
						description: `HTTP ${response.status} from ${url}`,
					},
					{ kind: "http", status: response.status },
				),
			);
		}

		const contentType = response.headers.get("content-type");
		if (expectedContentType !== null && !matchesContentType(contentType, expectedContentType)) {
			void response.body?.cancel().catch(() => {});
			const actual = contentType?.trim() || "<missing>";
			return err(
				fetchFailure(
					{
						code: InternalErrorCode.Network,
						description: `Unexpected Content-Type '${actual}' from ${url}, expected '${expectedContentType}'`,
					},
					{ kind: "response" },
				),
			);
		}

		if (!response.body)
			return err(
				fetchFailure(
					{
						code: InternalErrorCode.Network,
						description: `Empty response body from ${url}`,
					},
					{ kind: "response" },
				),
			);
		const body = await readResponseBody(
			response,
			options?.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES,
			controller.signal,
		);
		return ok(body);
	} catch (cause) {
		if (
			controller.signal.aborted ||
			(cause instanceof DOMException && cause.name === "AbortError")
		) {
			return err(
				fetchFailure(
					{
						code: InternalErrorCode.Timeout,
						description: `Request aborted or timed out: ${url}`,
						cause,
					},
					{ kind: timedOut && !options?.signal?.aborted ? "timeout" : "cancelled" },
				),
			);
		}
		return err(
			fetchFailure(
				{
					code: InternalErrorCode.Network,
					description:
						cause instanceof RangeError
							? `Response too large from ${url}`
							: cause instanceof Error
								? cause.message
								: `Network error fetching ${url}`,
					cause,
				},
				{ kind: receivedResponse ? "response" : "transport" },
			),
		);
	} finally {
		clearTimeout(timer);
		options?.signal?.removeEventListener("abort", onAbort);
	}
}

/** Decode only for cache lifetime (§10.2); callers still validate signatures and claims. */
function statementCacheTtl(jwt: string, options: FederationOptions): number {
	const decoded = decodeEntityStatement(jwt, options);
	const exp = decoded.ok ? decoded.value.payload.exp : undefined;
	if (typeof exp !== "number" || !Number.isFinite(exp)) return 0;
	const remaining = exp - nowSeconds(options?.clock);
	const ttl = Math.min(remaining, options?.cacheMaxTtlSeconds ?? DEFAULT_CACHE_TTL_SECONDS);
	return Number.isFinite(ttl) && ttl > 0 ? ttl : 0;
}

async function cachedStatement(
	key: string,
	options: FederationOptions,
): Promise<string | undefined> {
	if (!options?.cache) return undefined;
	let cached: string | undefined;
	try {
		cached = await options.cache.get<string>(key);
	} catch (error) {
		safeLogger(options.logger)?.error("Failed to read the federation cache");
		throw error;
	}
	if (cached === undefined) return undefined;
	if (statementCacheTtl(cached, options) > 0) return cached;
	try {
		await options.cache.delete(key);
	} catch (error) {
		safeLogger(options.logger)?.error("Failed to delete an expired federation cache entry");
		throw error;
	}
	return undefined;
}

/** Cache only unexpired statements, propagating storage failures to the caller. */
async function cacheStatement(key: string, jwt: string, options: FederationOptions): Promise<void> {
	const ttl = statementCacheTtl(jwt, options);
	if (!options.cache || ttl <= 0) return;
	try {
		await options.cache.set(key, jwt, ttl);
	} catch (error) {
		safeLogger(options.logger)?.error("Failed to write the federation cache");
		throw error;
	}
}

/** Fetch an Entity Configuration using §9.1 GET discovery, without a Federation client assertion. */
export async function fetchEntityConfiguration(
	entityId: EntityId,
	options: FederationOptions,
): Promise<Result<string, FederationError>> {
	const base = entityId.endsWith("/") ? entityId.slice(0, -1) : entityId;
	const url = `${base}${WELL_KNOWN_OPENID_FEDERATION}`;

	if (options?.cache) {
		const cacheKey = await ecCacheKey(entityId, options.engine);
		const cached = await cachedStatement(cacheKey, options);
		if (cached !== undefined) {
			safeLogger(options?.logger)?.debug("Cache hit for entity configuration");
			return ok(cached);
		}
	}

	safeLogger(options?.logger)?.debug("Fetching entity configuration");
	const result = await performFetch(url, {
		...options,
		method: "GET",
		expectedStatus: 200,
		federationErrors: true,
	});

	if (
		!result.ok &&
		result.error.code === InternalErrorCode.Network &&
		httpFailureStatus(result.error) === 404
	)
		return err(
			fetchFailure(
				{ code: FederationErrorCode.NotFound, description: "Entity Configuration not found" },
				{ kind: "http", status: 404 },
			),
		);

	if (result.ok && options?.cache) {
		const cacheKey = await ecCacheKey(entityId, options.engine);
		await cacheStatement(cacheKey, result.value, options);
	}

	return result;
}

export interface FetchSubordinateStatementOptions extends FederationOptions {
	/** Actual issuer identifier for isolating cached attestations when it is known. */
	issuer?: EntityId;
}

/** Fetch a Subordinate Statement about a subject from a superior's fetch endpoint. */
export async function fetchSubordinateStatement(
	fetchEndpoint: string,
	subject: EntityId,
	options: FetchSubordinateStatementOptions,
): Promise<Result<string, FederationError>> {
	let url: URL;
	try {
		url = new URL(fetchEndpoint);
	} catch (cause) {
		return err({
			code: InternalErrorCode.Network,
			description: `Invalid URL: ${fetchEndpoint}`,
			cause,
		});
	}

	if (options?.cache) {
		const issuer = options.issuer ?? (url.origin as EntityId);
		const cacheKey = await esCacheKey(issuer, subject, options.engine);
		const cached = await cachedStatement(cacheKey, options);
		if (cached !== undefined) {
			safeLogger(options?.logger)?.debug("Cache hit for subordinate statement");
			return ok(cached);
		}
	}

	safeLogger(options?.logger)?.debug("Fetching subordinate statement");
	const result = await fetchFederationEndpoint(
		url.toString(),
		new URLSearchParams({ sub: subject }),
		{
			...options,
			method: "GET",
			expectedStatus: 200,
			federationErrors: true,
		},
		options?.issuer,
	);

	if (
		!result.ok &&
		result.error.code === InternalErrorCode.Network &&
		httpFailureStatus(result.error) === 404
	)
		return err(
			fetchFailure(
				{ code: FederationErrorCode.NotFound, description: "Subordinate Statement not found" },
				{ kind: "http", status: 404 },
			),
		);

	if (result.ok && options?.cache) {
		const issuer = options.issuer ?? (url.origin as EntityId);
		const cacheKey = await esCacheKey(issuer, subject, options.engine);
		await cacheStatement(cacheKey, result.value, options);
	}

	return result;
}
