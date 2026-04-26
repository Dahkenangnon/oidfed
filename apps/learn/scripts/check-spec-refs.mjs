#!/usr/bin/env node
/**
 * Walks every lesson file under app/routes/lessons/, extracts every <SpecRef sec="..." />
 * usage, and confirms the referenced section exists in artifacts/spec-sections/.
 *
 * A SpecRef is valid if its top-level section number §N (and optionally §N.M, §N.M.O)
 * matches one of the 21 spec-section files. Sub-section depth is verified by reading
 * the file body and confirming a heading like "### N.M." or "#### N.M.O." exists.
 *
 * Usage: node apps/learn/scripts/check-spec-refs.mjs
 */
import { readFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";

const LESSONS_DIR = resolve(import.meta.dirname, "..", "app", "routes", "lessons");
const SPEC_DIR = resolve(import.meta.dirname, "..", "..", "..", "..", "artifacts", "spec-sections");

const sectionFiles = readdirSync(SPEC_DIR).filter((f) => f.endsWith(".txt"));
const sectionByNumber = new Map();
for (const f of sectionFiles) {
	const m = f.match(/^section-(\d+)-/);
	if (m) sectionByNumber.set(Number(m[1]), join(SPEC_DIR, f));
}

const SPEC_REF_RE = /<SpecRef\s+sec="([^"]+)"/g;

// Escape every regex metacharacter (backslash first, then the rest) so the
// caller-supplied section identifier is treated as a literal string.
function escapeRegex(s) {
	return s.replace(/[\\.*+?^${}()|[\]]/g, "\\$&");
}

function checkSubsection(top, full) {
	if (!sectionByNumber.has(top)) return false;
	if (full === String(top)) return true;
	const body = readFileSync(sectionByNumber.get(top), "utf8");
	// Match "### 7.2." or "#### 5.1.1." etc., looking for exact level
	const escaped = escapeRegex(full);
	const re = new RegExp(`^#+ ${escaped}\\.`, "m");
	return re.test(body);
}

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
		const top = Number(sec.split(".")[0]);
		if (!checkSubsection(top, sec)) {
			failures.push({ file, sec });
		}
	}
}

if (failures.length) {
	console.error(`✗ ${failures.length} of ${total} spec refs failed validation:\n`);
	for (const f of failures) {
		console.error(`  ${f.file}: §${f.sec} not found in spec-sections/`);
	}
	process.exit(1);
}

console.log(`✓ ${total} spec refs verified across ${lessonFiles.length} lessons`);
