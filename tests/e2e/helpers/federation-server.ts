import { readFileSync } from "node:fs";
import https from "node:https";
import { join } from "node:path";
import type { Express } from "express";

const CERT_DIR = join(import.meta.dirname, "../../../.certs");

export interface FederationTestServer {
	readonly port: number;
	addEntity(entityId: string, app: Express): void;
	close(): Promise<void>;
}

export interface FederationServerOptions {
	/** Port to bind to. Defaults to 0 (ephemeral). */
	port?: number;
	/** Host to bind to. Defaults to "127.0.0.1". */
	host?: string;
}

export async function createAndStartFederationTestServer(
	options?: FederationServerOptions,
): Promise<FederationTestServer> {
	const cert = readFileSync(join(CERT_DIR, "ofed.pem"));
	const key = readFileSync(join(CERT_DIR, "ofed-key.pem"));

	const vhosts = new Map<string, Express>();

	const server = https.createServer({ cert, key }, (req, res) => {
		// CORS: allow browser-based tools (e.g. @oidfed/explorer) to access federation endpoints
		const origin = req.headers.origin;
		if (origin) {
			res.setHeader("Access-Control-Allow-Origin", origin);
			res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
			res.setHeader("Access-Control-Allow-Headers", "Content-Type, Accept");
			res.setHeader("Access-Control-Max-Age", "86400");
		}

		// Handle CORS preflight
		if (req.method === "OPTIONS") {
			res.writeHead(204);
			res.end();
			return;
		}

		const host = (req.headers.host ?? "").replace(/:\d+$/, "");
		const app = vhosts.get(host);
		if (typeof app !== "function") {
			res.writeHead(404, { "Content-Type": "text/plain" });
			res.end(`No vhost for ${host}`);
			return;
		}
		app(req, res);
	});

	const bindPort = options?.port ?? 0;
	const bindHost = options?.host ?? "127.0.0.1";

	const port = await new Promise<number>((resolve) => {
		server.listen(bindPort, bindHost, () => {
			const addr = server.address();
			resolve(typeof addr === "object" && addr ? addr.port : 0);
		});
	});

	return {
		get port() {
			return port;
		},

		addEntity(entityId: string, app: Express) {
			const url = new URL(entityId);
			vhosts.set(url.hostname, app);
		},

		close() {
			return new Promise<void>((resolve, reject) => {
				server.close((err) => (err ? reject(err) : resolve()));
			});
		},
	};
}
