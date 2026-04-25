import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { expect, test } from "@playwright/test";

const script = readFileSync("./tests/tap/.build/run-browser.js", "utf-8");

test("passes tests", async ({ page }) => {
	const server = createServer((req, res) => {
		if (req.url === "/run-browser.js") {
			res.writeHead(200, { "Content-Type": "application/javascript" });
			res.end(script);
		} else {
			res.writeHead(200, { "Content-Type": "text/html" });
			res.end(
				'<!DOCTYPE html><html><head></head><body><script type="module" src="/run-browser.js"></script></body></html>',
			);
		}
	});

	await new Promise<void>((resolve) => server.listen(0, resolve));
	const port = (server.address() as import("node:net").AddressInfo).port;

	page.on("console", (msg) => {
		if (msg.type() === "log") console.log(msg.text());
	});

	await page.goto(`http://localhost:${port}`);

	let stats: unknown;
	do {
		await page.waitForTimeout(1000);
		stats = await page.evaluate(() => (globalThis as unknown as { stats: unknown }).stats);
	} while (!stats);

	server.close();
	expect((stats as { failed: number }).failed).toBe(0);
});
