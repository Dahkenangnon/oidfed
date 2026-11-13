import { FederationErrorCode, JWT_BEARER_CLIENT_ASSERTION_TYPE } from "./constants.js";
import { err, type Result } from "./errors.js";
import { signEntityStatement } from "./jose/sign.js";
import type { JwtSigner } from "./jose/signer.js";
import { type PerformFetchOptions, performFetch } from "./trust-chain/fetch.js";
import { entityId, nowSeconds } from "./types.js";

export interface PrivateKeyJwtEndpointAuthentication {
	readonly method: "private_key_jwt";
	readonly clientId: string;
	readonly audience: string;
	readonly signer: JwtSigner;
}
export interface CustomEndpointClientAuthentication {
	readonly method: string;
	/** Explicit responder identity for any credential audience binding. */
	readonly audience: string;
	readonly prepare: (input: Readonly<{ endpoint: string; audience: string }>) =>
		| {
				readonly parameters?: Readonly<Record<string, string>>;
				readonly headers?: Readonly<Record<string, string>>;
		  }
		| Promise<{
				readonly parameters?: Readonly<Record<string, string>>;
				readonly headers?: Readonly<Record<string, string>>;
		  }>;
}
export type EndpointClientAuthentication =
	| PrivateKeyJwtEndpointAuthentication
	| CustomEndpointClientAuthentication;
export type EndpointAdditionalParameters = Readonly<Record<string, string | readonly string[]>>;
const reserved = new Set([
	"trust_mark_type",
	"sub",
	"trust_mark",
	"client_id",
	"client_assertion",
	"client_assertion_type",
	"client_secret",
]);

/** Compose authenticated POST or anonymous requests without rewriting fixed selectors. */
export async function fetchFederationEndpoint(
	endpoint: string,
	selectors: URLSearchParams,
	options: PerformFetchOptions,
	expectedAudience?: string,
): Promise<Result<string>> {
	try {
		const url = new URL(endpoint);
		if (url.protocol !== "https:")
			return err({
				code: FederationErrorCode.InvalidRequest,
				description: "Endpoint URL must use https",
			});
		if (url.href.includes("#") || url.username || url.password)
			throw new Error("Invalid endpoint URL");
		const form = new URLSearchParams(selectors);
		for (const [name, value] of Object.entries(options.additionalParameters ?? {})) {
			if (reserved.has(name))
				throw new Error("Additional parameters cannot replace protocol selectors or credentials");
			const values = typeof value === "string" ? [value] : value;
			if (!Array.isArray(values) || values.some((v) => typeof v !== "string"))
				throw new Error("Invalid additional parameter values");
			for (const item of values) form.append(name, item);
		}
		for (const name of new Set(form.keys())) {
			if (!url.searchParams.has(name)) continue;
			const fixed = url.searchParams.getAll(name),
				supplied = form.getAll(name);
			if (fixed.length !== supplied.length || fixed.some((v, i) => v !== supplied[i]))
				throw new Error("Parameters conflict with endpoint fixed query");
		}
		const auth = options.authentication;
		const headers = new Headers();
		if (auth) {
			const audience = entityId(auth.audience);
			if (expectedAudience !== undefined && audience !== expectedAudience)
				throw new Error("Authentication audience must match the responder Entity Identifier");
			if (auth.method === "private_key_jwt" && "signer" in auth) {
				const clientId = entityId(auth.clientId),
					now = nowSeconds(options.clock);
				const assertion = await signEntityStatement(
					{
						iss: clientId,
						sub: clientId,
						aud: audience,
						iat: now,
						exp: now + 60,
						jti: crypto.randomUUID(),
					},
					auth.signer,
					{ typ: "JWT" },
				);
				form.set("client_assertion_type", JWT_BEARER_CLIENT_ASSERTION_TYPE);
				form.set("client_assertion", assertion);
			} else if (
				"prepare" in auth &&
				typeof auth.prepare === "function" &&
				auth.method !== "none" &&
				auth.method !== "private_key_jwt"
			) {
				const prepared = await auth.prepare(Object.freeze({ endpoint: url.href, audience }));
				if (!prepared || typeof prepared !== "object")
					throw new Error("Invalid authentication output");
				for (const [name, value] of Object.entries(prepared.parameters ?? {})) {
					if (
						form.has(name) ||
						url.searchParams.has(name) ||
						["trust_mark", "trust_mark_type", "sub"].includes(name) ||
						typeof value !== "string"
					)
						throw new Error("Authentication cannot override request selectors");
					form.set(name, value);
				}
				for (const [name, value] of Object.entries(prepared.headers ?? {})) {
					if (
						["content-type", "content-length", "host", "accept"].includes(name.toLowerCase()) ||
						typeof value !== "string"
					)
						throw new Error("Invalid authentication header");
					headers.set(name, value);
				}
			} else throw new Error("Unsupported client authentication");
			// Never send credentials already embedded in an advertised endpoint query.
			if (
				["client_assertion", "client_assertion_type", "client_secret"].some((name) =>
					url.searchParams.has(name),
				)
			)
				throw new Error("Endpoint query contains credentials");
		}
		const method = auth ? "POST" : (options.method ?? "GET");
		if (method === "GET")
			for (const name of new Set(form.keys()))
				if (!url.searchParams.has(name))
					for (const value of form.getAll(name)) url.searchParams.append(name, value);
		return performFetch(url.href, {
			...options,
			method,
			...(method === "POST" ? { body: form } : {}),
			headers,
			redirect: "error",
		});
	} catch {
		return err({
			code: FederationErrorCode.InvalidRequest,
			description: "Invalid federation endpoint request or authentication configuration",
		});
	}
}
