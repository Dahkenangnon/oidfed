#!/usr/bin/env node
/**
 * Walks every lesson file under app/routes/lessons/, extracts every <SpecRef sec="..." />
 * usage, and confirms the referenced section is a known OpenID Federation section.
 *
 * Keep the allowlist focused on section anchors used by the course. Adding a new
 * SpecRef should update KNOWN_SPEC_SECTIONS in the same change.
 *
 * Usage: node apps/learn/scripts/check-spec-refs.mjs
 */
import { readFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";

const LESSONS_DIR = resolve(import.meta.dirname, "..", "app", "routes", "lessons");

const SPEC_REF_RE = /<SpecRef\s+sec="([^"]+)"/g;
const KNOWN_SPEC_SECTIONS = new Set([
	"1.2",
	"3",
	"3.1.1",
	"3.1.2",
	"3.1.3",
	"3.2",
	"4",
	"4.1",
	"5",
	"5.1",
	"6.1",
	"6.1.3.1",
	"6.1.4",
	"6.2.1",
	"6.2.2",
	"7",
	"7.1",
	"7.2",
	"7.3",
	"8",
	"8.1",
	"9",
	"10",
	"10.1",
	"10.2",
	"12",
	"12.1",
	"12.1.1",
	"12.2",
	"15",
]);

const lessonFiles = readdirSync(LESSONS_DIR).filter(
	(f) => f.startsWith("lesson-") && f.endsWith(".tsx"),
);

let total = 0;
const failures = [];

for (const file of lessonFiles) {
	const src = readFileSync(join(LESSONS_DIR, file), "utf8");
	for (const m of src.matchAll(SPEC_REF_RE)) {
		total++;
		const sec = m[1];
		if (!KNOWN_SPEC_SECTIONS.has(sec)) {
			failures.push({ file, sec });
		}
	}
}

if (failures.length) {
	console.error(`✗ ${failures.length} of ${total} spec refs failed validation:\n`);
	for (const f of failures) {
		console.error(`  ${f.file}: §${f.sec} is not in KNOWN_SPEC_SECTIONS`);
	}
	process.exit(1);
}

console.log(`✓ ${total} spec refs verified across ${lessonFiles.length} lessons`);
