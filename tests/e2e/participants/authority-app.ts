import type { AuthorityServer } from "@oidfed/authority";
import express from "express";

export function createAuthorityApp(authority: AuthorityServer, entityId: string): express.Express {
	const app = express();
	app.use(express.raw({ type: "application/entity-statement+jwt", limit: "64kb" }));
	app.use(express.urlencoded({ extended: false, limit: "64kb" }));

	const federationHandler = authority.handler();

	app.all("/*splat", async (req, res) => {
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

	return app;
}
