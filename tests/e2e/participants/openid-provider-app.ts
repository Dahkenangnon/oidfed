import type { AuthorityServer } from "@oidfed/authority";
import type { EntityId, JWK, TrustAnchorSet } from "@oidfed/core";
import { decodeEntityStatement, InMemoryJtiStore } from "@oidfed/core";
import { processAutomaticRegistration } from "@oidfed/oidc";
import express from "express";
import Provider from "oidc-provider";

export interface OpenIDProviderAppConfig {
	authority: AuthorityServer;
	entityId: string;
	trustAnchors: TrustAnchorSet;
	/** OP signing key — reused for OIDC ID-token signing in the test bed. */
	signingKey: JWK;
}

/**
 * E2E OP participant.
 *
 * Exposes:
 *   • Federation surface via `authority.handler()`
 *   • GET /auth — intercepts `?request=` (and `?request_uri=https://…`), runs
 *     `processAutomaticRegistration`, pre-registers the resulting RP into the
 *     in-memory client store, then forwards to node-oidc-provider.
 *   • POST /auth — same as GET /auth but with `request` in the form body.
 *   • POST /request — PAR endpoint. Intercepts before node-oidc-provider's
 *     client-auth middleware runs, federation-pre-registers the RP, then
 *     forwards. node-oidc-provider's PAR handler then validates the
 *     `client_assertion` against the now-registered client and emits a
 *     201 with a `urn:`-style request_uri.
 *
 * In-memory adapter scoped per-process — fine for tests, not for production.
 */
export function createOpenIDProviderApp(config: OpenIDProviderAppConfig): express.Express {
	const { authority, entityId, trustAnchors, signingKey } = config;
	const app = express();

	const clientStore = new Map<string, StoredClient>();
	const Adapter = createInMemoryAdapter(clientStore);
	const jtiStore = new InMemoryJtiStore();
	const federationHandler = authority.handler();

	const oidc = new Provider(entityId, {
		adapter: Adapter,
		jwks: { keys: [signingKey] },
		claims: { openid: ["sub"] },
		scopes: ["openid"],
		responseTypes: ["code"],
		clientAuthMethods: ["private_key_jwt", "none"],
		ttl: {
			AuthorizationCode: 60,
			IdToken: 600,
			AccessToken: 600,
			Interaction: 300,
			Session: 600,
			Grant: 300,
		},
		findAccount: async (_ctx: unknown, id: string) => ({
			accountId: id,
			async claims() {
				return { sub: id };
			},
		}),
		features: {
			registration: { enabled: false },
			requestObjects: { enabled: true },
			pushedAuthorizationRequests: { enabled: true },
		},
	});

	oidc.proxy = true;

	app.use(express.raw({ type: "application/entity-statement+jwt", limit: "64kb" }));
	app.use(express.urlencoded({ extended: false, limit: "128kb" }));

	// Federation endpoints
	app.all("/.well-known/openid-federation", async (req, res) => {
		const url = new URL(req.originalUrl, entityId);
		const request = new Request(url.toString(), { method: "GET" });
		const response = await federationHandler(request);
		res.status(response.status);
		for (const [key, value] of response.headers) {
			res.setHeader(key, value);
		}
		res.send(await response.text());
	});

	for (const path of [
		"/federation_fetch",
		"/federation_list",
		"/federation_resolve",
		"/federation_registration",
		"/federation_trust_mark",
		"/federation_trust_mark_status",
		"/federation_trust_mark_list",
	]) {
		app.all(path, async (req, res) => {
			const request = await toFetchRequest(req, entityId);
			const response = await federationHandler(request);
			res.status(response.status);
			for (const [key, value] of response.headers) {
				res.setHeader(key, value);
			}
			res.send(await response.text());
		});
	}

	// Federation-aware intercept that processes the Request Object and
	// pre-registers the RP into the OIDC client store. Returns true if the
	// caller should respond with a JSON 400, in which case it has already
	// populated `errorBody`. Returns false and continues to next() on success.
	async function preregister(
		requestJwt: string,
	): Promise<{ ok: true } | { ok: false; errorCode: string; errorDescription: string }> {
		const result = await processAutomaticRegistration(requestJwt, trustAnchors, {
			opEntityId: entityId as EntityId,
			jtiStore,
			httpClient: fetch,
		});
		if (!result.ok) {
			return {
				ok: false,
				errorCode: result.error.code,
				errorDescription: result.error.description,
			};
		}
		const rpMeta = result.value.resolvedRpMetadata as Record<string, unknown>;
		const leafStmt = result.value.trustChain.statements[0];
		const fedJwks = leafStmt?.payload.jwks as { keys: JWK[] } | undefined;
		const rpJwks = (rpMeta.jwks as { keys: JWK[] } | undefined) ?? fedJwks;
		registerClient(clientStore, {
			client_id: result.value.rpEntityId,
			redirect_uris: (rpMeta.redirect_uris as string[]) || [],
			response_types: (rpMeta.response_types as string[]) || ["code"],
			grant_types: (rpMeta.grant_types as string[]) || ["authorization_code"],
			token_endpoint_auth_method: "private_key_jwt",
			token_endpoint_auth_signing_alg: "ES256",
			id_token_signed_response_alg: "ES256",
			request_object_signing_alg: "ES256",
			jwks: rpJwks,
			application_type: "web",
		});
		return { ok: true };
	}

	// GET /auth — intercepts ?request= and ?request_uri=https://…
	app.get("/auth", async (req, res, next) => {
		const requestJwt = req.query.request as string | undefined;
		const requestUri = req.query.request_uri as string | undefined;

		let inboundJwt: string | undefined;
		if (typeof requestJwt === "string") {
			inboundJwt = requestJwt;
		} else if (typeof requestUri === "string" && requestUri.startsWith("https://")) {
			const fetchResp = await fetch(requestUri);
			if (fetchResp.ok) inboundJwt = await fetchResp.text();
		}

		if (inboundJwt) {
			const pre = await preregister(inboundJwt);
			if (!pre.ok) {
				res.status(400).json({ error: pre.errorCode, error_description: pre.errorDescription });
				return;
			}
		}

		const handler = oidc.callback() as express.RequestHandler;
		return handler(req, res, next);
	});

	// POST /auth — form_post entrypoint
	app.post("/auth", async (req, res, next) => {
		const body = req.body as Record<string, unknown> | undefined;
		const requestJwt = body?.request;
		if (typeof requestJwt === "string") {
			const pre = await preregister(requestJwt);
			if (!pre.ok) {
				res.status(400).json({ error: pre.errorCode, error_description: pre.errorDescription });
				return;
			}
		}
		const handler = oidc.callback() as express.RequestHandler;
		return handler(req, res, next);
	});

	// POST /request — PAR interceptor: federation-pre-register, then defer to oidc.
	app.post("/request", async (req, res, next) => {
		const body = req.body as Record<string, unknown> | undefined;
		const requestJwt = body?.request;
		if (typeof requestJwt === "string") {
			const pre = await preregister(requestJwt);
			if (!pre.ok) {
				res.status(400).json({ error: pre.errorCode, error_description: pre.errorDescription });
				return;
			}
		}
		const handler = oidc.callback() as express.RequestHandler;
		return handler(req, res, next);
	});

	// Standard OIDC endpoints
	app.use("/", oidc.callback() as express.RequestHandler);

	// Suppress "decodeEntityStatement imported but unused" if reorganization removes the need.
	void decodeEntityStatement;

	return app;
}

// -------------------------------------------------------------------------
// In-memory adapter for node-oidc-provider
// -------------------------------------------------------------------------

interface StoredClient {
	client_id: string;
	client_secret?: string | undefined;
	redirect_uris: string[];
	response_types: string[];
	grant_types: string[];
	token_endpoint_auth_method: string;
	token_endpoint_auth_signing_alg?: string | undefined;
	id_token_signed_response_alg?: string | undefined;
	request_object_signing_alg?: string | undefined;
	jwks?: { keys: JWK[] } | undefined;
	application_type: "web" | "native";
}

function registerClient(store: Map<string, StoredClient>, client: StoredClient): void {
	const sanitized: StoredClient = {
		...client,
		redirect_uris: client.redirect_uris.filter(
			(u) => typeof u === "string" && u.startsWith("https://"),
		),
	};
	store.set(client.client_id, sanitized);
}

function createInMemoryAdapter(clientStore: Map<string, StoredClient>) {
	interface Slot {
		payload: Record<string, unknown>;
		expiresAt: number;
	}
	const stores = new Map<string, Map<string, Slot>>();
	const byUid = new Map<string, Map<string, string>>();
	const byUserCode = new Map<string, Map<string, string>>();
	const grantGroups = new Map<string, Set<string>>();

	function bucket(name: string): Map<string, Slot> {
		let s = stores.get(name);
		if (!s) {
			s = new Map();
			stores.set(name, s);
		}
		return s;
	}

	return class Adapter {
		readonly name: string;
		constructor(name: string) {
			this.name = name;
		}

		async upsert(id: string, payload: Record<string, unknown>, expiresIn: number): Promise<void> {
			if (this.name === "Client") return;
			const expiresAt = expiresIn ? Date.now() + expiresIn * 1000 : Number.MAX_SAFE_INTEGER;
			bucket(this.name).set(id, { payload, expiresAt });
			const uid = payload.uid;
			if (typeof uid === "string") {
				let m = byUid.get(this.name);
				if (!m) {
					m = new Map();
					byUid.set(this.name, m);
				}
				m.set(uid, id);
			}
			const userCode = payload.userCode;
			if (typeof userCode === "string") {
				let m = byUserCode.get(this.name);
				if (!m) {
					m = new Map();
					byUserCode.set(this.name, m);
				}
				m.set(userCode, id);
			}
			const grantId = payload.grantId;
			if (typeof grantId === "string") {
				let g = grantGroups.get(grantId);
				if (!g) {
					g = new Set();
					grantGroups.set(grantId, g);
				}
				g.add(`${this.name}:${id}`);
			}
		}

		async find(id: string): Promise<Record<string, unknown> | undefined> {
			if (this.name === "Client") {
				const c = clientStore.get(id);
				return c ? (c as unknown as Record<string, unknown>) : undefined;
			}
			const slot = bucket(this.name).get(id);
			if (!slot) return undefined;
			if (slot.expiresAt && slot.expiresAt < Date.now()) {
				bucket(this.name).delete(id);
				return undefined;
			}
			return slot.payload;
		}

		async findByUid(uid: string): Promise<Record<string, unknown> | undefined> {
			const id = byUid.get(this.name)?.get(uid);
			return id ? this.find(id) : undefined;
		}

		async findByUserCode(userCode: string): Promise<Record<string, unknown> | undefined> {
			const id = byUserCode.get(this.name)?.get(userCode);
			return id ? this.find(id) : undefined;
		}

		async consume(id: string): Promise<void> {
			const slot = bucket(this.name).get(id);
			if (slot) {
				slot.payload.consumed = Math.floor(Date.now() / 1000);
			}
		}

		async destroy(id: string): Promise<void> {
			bucket(this.name).delete(id);
		}

		async revokeByGrantId(grantId: string): Promise<void> {
			const g = grantGroups.get(grantId);
			if (!g) return;
			for (const key of g) {
				const sep = key.indexOf(":");
				const name = key.slice(0, sep);
				const id = key.slice(sep + 1);
				stores.get(name)?.delete(id);
			}
			grantGroups.delete(grantId);
		}
	};
}

async function toFetchRequest(req: express.Request, entityIdBase: string): Promise<Request> {
	const url = new URL(req.originalUrl, entityIdBase);
	const hasBody = req.method !== "GET" && req.method !== "HEAD";
	let body: string | Uint8Array | undefined;
	if (hasBody) {
		if (Buffer.isBuffer(req.body)) {
			body = new Uint8Array(req.body);
		} else if (typeof req.body === "object" && req.body !== null) {
			body = new URLSearchParams(req.body as Record<string, string>).toString();
		}
	}
	return new Request(url.toString(), {
		method: req.method,
		headers: req.headers as Record<string, string>,
		...(body !== undefined ? { body } : {}),
	});
}
