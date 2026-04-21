import type { AuthorityServer } from "@oidfed/authority";
import type { EntityId, TrustAnchorSet } from "@oidfed/core";
import { InMemoryJtiStore } from "@oidfed/core";
import { processAutomaticRegistration } from "@oidfed/oidc";
import express from "express";
import Provider from "oidc-provider";

export interface OpenIDProviderAppConfig {
	authority: AuthorityServer;
	entityId: string;
	trustAnchors: TrustAnchorSet;
}

export function createOpenIDProviderApp(config: OpenIDProviderAppConfig): express.Express {
	const { authority, entityId, trustAnchors } = config;
	const app = express();
	app.use(express.raw({ type: "application/entity-statement+jwt", limit: "64kb" }));
	app.use(express.urlencoded({ extended: false, limit: "64kb" }));

	const jtiStore = new InMemoryJtiStore();
	const federationHandler = authority.handler();

	// OIDC Provider (panva/node-oidc-provider)
	const oidc = new Provider(entityId, {
		clients: [],
		findAccount: async (_ctx: unknown, id: string) => ({
			accountId: id,
			async claims() {
				return { sub: id };
			},
		}),
		features: {
			registration: { enabled: false },
		},
	});

	// Trust the proxy (Express behind HTTPS)
	oidc.proxy = true;

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

	// Federation fetch/list/resolve/registration endpoints
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
			const url = new URL(req.originalUrl, entityId);
			const hasBody = req.method !== "GET" && req.method !== "HEAD";
			let body: BodyInit | undefined;
			if (hasBody) {
				if (Buffer.isBuffer(req.body)) {
					body = req.body;
				} else if (typeof req.body === "object" && req.body !== null) {
					body = new URLSearchParams(req.body as Record<string, string>).toString();
				}
			}
			const request = new Request(url.toString(), {
				method: req.method,
				headers: req.headers as Record<string, string>,
				...(body !== undefined ? { body } : {}),
			});
			const response = await federationHandler(request);
			res.status(response.status);
			for (const [key, value] of response.headers) {
				res.setHeader(key, value);
			}
			res.send(await response.text());
		});
	}

	// Automatic registration: intercept /auth with ?request= parameter
	app.get("/auth", async (req, res, next) => {
		const requestJwt = req.query.request as string | undefined;

		if (requestJwt) {
			const result = await processAutomaticRegistration(requestJwt, trustAnchors, {
				opEntityId: entityId as EntityId,
				jtiStore,
				httpClient: fetch,
			});

			if (!result.ok) {
				res.status(400).json({
					error: result.error.code,
					error_description: result.error.description,
				});
				return;
			}
		}

		// Forward to node-oidc-provider
		const handler = oidc.callback() as express.RequestHandler;
		return handler(req, res, next);
	});

	// Standard OIDC endpoints
	app.use("/", oidc.callback() as express.RequestHandler);

	return app;
}
