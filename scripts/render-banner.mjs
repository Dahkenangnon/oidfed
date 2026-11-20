/** Rasterize a package banner SVG to the 2172x724 PNG referenced by that package's README. */

import { readFileSync } from "node:fs";
import { chromium } from "@playwright/test";

const WIDTH = 2172;
const HEIGHT = 724;

const [svgPath, outPath] = process.argv.slice(2);
if (!svgPath || !outPath) {
	console.error("Usage: node scripts/render-banner.mjs <source.svg> <output.png>");
	process.exit(1);
}

const svg = readFileSync(svgPath, "utf8");
const page = `<!doctype html><meta charset="utf-8">
<style>html,body{margin:0;padding:0;background:#fff}svg{display:block}</style>${svg}`;

const browser = await chromium.launch();
try {
	const tab = await browser.newPage({
		viewport: { width: WIDTH, height: HEIGHT },
		deviceScaleFactor: 1,
	});
	await tab.setContent(page, { waitUntil: "load" });
	await tab.evaluate(() => document.fonts.ready);
	await tab.screenshot({ path: outPath, clip: { x: 0, y: 0, width: WIDTH, height: HEIGHT } });
} finally {
	await browser.close();
}

console.log(`Rendered ${svgPath} -> ${outPath} (${WIDTH}x${HEIGHT})`);
