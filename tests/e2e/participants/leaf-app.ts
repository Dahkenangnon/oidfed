import type { LeafEntity } from "@oidfed/leaf";
import express from "express";

export function createLeafApp(leaf: LeafEntity, entityId: string): express.Express {
	const app = express();
	const leafHandler = leaf.handler();

	app.get("/.well-known/openid-federation", async (req, res) => {
		const url = new URL(req.originalUrl, entityId);
		const request = new Request(url.toString(), { method: "GET" });
		const response = await leafHandler(request);

		res.status(response.status);
		for (const [key, value] of response.headers) {
			res.setHeader(key, value);
		}
		res.send(await response.text());
	});

	return app;
}
