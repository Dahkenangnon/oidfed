import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { Agent, setGlobalDispatcher } from "undici";
import { afterAll, beforeAll } from "vitest";

const CERT_DIR = join(import.meta.dirname, "../../../.certs");

let agent: Agent | undefined;

beforeAll(() => {
	const caPathFile = join(CERT_DIR, "ca-path.txt");

	if (!existsSync(caPathFile)) {
		throw new Error("E2E certs not found. Run `pnpm setup:e2e` first to generate certificates.");
	}

	const caRoot = readFileSync(caPathFile, "utf-8").trim();
	const ca = readFileSync(join(caRoot, "rootCA.pem"), "utf-8");

	agent = new Agent({
		connect: {
			ca,
			lookup(_hostname, _options, callback) {
				callback(null, [{ address: "127.0.0.1", family: 4 }]);
			},
		},
	});

	setGlobalDispatcher(agent);
});

afterAll(async () => {
	await agent?.close();
});
