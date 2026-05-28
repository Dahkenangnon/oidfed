import type { LeafEntity } from "@oidfed/leaf";
import express from "express";

interface StoredRequestObject {
	jwt: string;
	expiresAt: number;
}

export interface RequestObjectStore {
	set(id: string, jwt: string, ttlMs: number): void;
	/** Returns the stored JWT and evicts the entry (single-use). */
	take(id: string): string | undefined;
	/** Test helper — true iff id is still present and not expired. */
	has(id: string): boolean;
}

export function createRequestObjectStore(): RequestObjectStore {
	const entries = new Map<string, StoredRequestObject>();

	function prune(): void {
		const now = Date.now();
		for (const [id, entry] of entries) {
			if (entry.expiresAt <= now) entries.delete(id);
		}
	}

	return {
		set(id, jwt, ttlMs) {
			prune();
			entries.set(id, { jwt, expiresAt: Date.now() + ttlMs });
		},
		take(id) {
			prune();
			const entry = entries.get(id);
			if (entry === undefined) return undefined;
			entries.delete(id);
			return entry.jwt;
		},
		has(id) {
			prune();
			return entries.has(id);
		},
	};
}

export function createLeafApp(
	leaf: LeafEntity,
	entityId: string,
	options?: { requestObjectStore?: RequestObjectStore },
): express.Express {
	const app = express();
	const leafHandler = leaf.handler();
	const store = options?.requestObjectStore;

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

	if (store !== undefined) {
		app.get("/request-object/:id", (req, res) => {
			const id = req.params.id;
			const jwt = store.take(id);
			if (jwt === undefined) {
				res.status(404).json({
					error: "not_found",
					error_description: "Request Object not found or expired.",
					entity_id: entityId,
				});
				return;
			}
			res.status(200);
			res.setHeader("content-type", "application/oauth-authz-req+jwt");
			res.setHeader("cache-control", "no-store");
			res.send(jwt);
		});
	}

	return app;
}
