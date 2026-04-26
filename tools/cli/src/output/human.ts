import { colors, isCompactJwt } from "./colors.js";
import type { OutputFormatter } from "./index.js";

const STATUS_OK = new Set(["ok", "active", "true"]);
const STATUS_ERR = new Set(["error", "expired", "revoked", "unreachable", "false"]);

function colorizeCell(value: unknown): string {
	if (typeof value === "boolean") {
		return value ? colors.ok("✓") : colors.error("✗");
	}
	const s = String(value ?? "");
	if (isCompactJwt(value)) {
		const [h = "", p = "", sig = ""] = s.split(".");
		return `${colors.jwtHeader(h)}.${colors.jwtPayload(p)}.${colors.jwtSignature(sig)}`;
	}
	const lower = s.toLowerCase();
	if (STATUS_OK.has(lower)) return colors.ok(s);
	if (STATUS_ERR.has(lower)) return colors.error(s);
	if (lower === "expiring_soon") return colors.warn(s);
	if (typeof value === "number") return colors.number(s);
	return s;
}

function stripAnsi(s: string): number {
	// biome-ignore lint/suspicious/noControlCharactersInRegex: ANSI strip
	return s.replace(/\x1b\[[0-9;]*m/g, "").length;
}

function padCell(content: string, width: number): string {
	const visible = stripAnsi(content);
	return content + " ".repeat(Math.max(0, width - visible));
}

function isDigit(c: string): boolean {
	return c >= "0" && c <= "9";
}

function isWordChar(c: string | undefined): boolean {
	if (c === undefined) return false;
	return (c >= "a" && c <= "z") || (c >= "A" && c <= "Z") || (c >= "0" && c <= "9") || c === "_";
}

/**
 * Colorize a JSON document for terminal output.
 *
 * Implemented as a single left-to-right pass over the input so that each
 * character is examined a constant number of times — no backtracking, no
 * regex on the raw input. The complexity is therefore linear in the input
 * length, which avoids the polynomial-time pitfalls of mixed-alternation
 * regular expressions on JSON-shaped strings.
 */
function colorizeJson(json: string): string {
	let out = "";
	let i = 0;
	const n = json.length;
	while (i < n) {
		const c = json[i] as string;
		if (c === '"') {
			let j = i + 1;
			let terminated = false;
			while (j < n) {
				const cj = json[j];
				if (cj === "\\") {
					j += 2;
					continue;
				}
				if (cj === '"') {
					j++;
					terminated = true;
					break;
				}
				j++;
			}
			const tokenEnd = terminated ? j : n;
			const literal = json.slice(i, tokenEnd);
			let k = tokenEnd;
			while (k < n && (json[k] === " " || json[k] === "\t")) k++;
			if (terminated && json[k] === ":") {
				out += colors.key(literal);
			} else {
				out += colors.string(literal);
			}
			i = tokenEnd;
			continue;
		}

		const startsKeyword = (c === "t" || c === "f" || c === "n") && !isWordChar(json[i - 1]);
		if (startsKeyword) {
			if (c === "t" && json.slice(i, i + 4) === "true" && !isWordChar(json[i + 4])) {
				out += colors.boolean("true");
				i += 4;
				continue;
			}
			if (c === "f" && json.slice(i, i + 5) === "false" && !isWordChar(json[i + 5])) {
				out += colors.boolean("false");
				i += 5;
				continue;
			}
			if (c === "n" && json.slice(i, i + 4) === "null" && !isWordChar(json[i + 4])) {
				out += colors.null("null");
				i += 4;
				continue;
			}
		}

		const numberStart =
			(c === "-" && isDigit(json[i + 1] ?? "")) || (isDigit(c) && !isWordChar(json[i - 1]));
		if (numberStart) {
			let j = i;
			if (json[j] === "-") j++;
			while (j < n && isDigit(json[j] as string)) j++;
			if (json[j] === ".") {
				j++;
				while (j < n && isDigit(json[j] as string)) j++;
			}
			if (json[j] === "e" || json[j] === "E") {
				j++;
				if (json[j] === "+" || json[j] === "-") j++;
				while (j < n && isDigit(json[j] as string)) j++;
			}
			out += colors.number(json.slice(i, j));
			i = j;
			continue;
		}

		out += c;
		i++;
	}
	return out;
}

export class HumanFormatter implements OutputFormatter {
	format(data: unknown): string {
		if (isCompactJwt(data)) {
			const [header = "", payload = "", signature = ""] = data.split(".");
			return `${colors.jwtHeader(header)}.${colors.jwtPayload(payload)}.${colors.jwtSignature(signature)}`;
		}

		if (Array.isArray(data) && data.length > 0 && typeof data[0] === "object" && data[0] !== null) {
			return formatTable(data as Record<string, unknown>[]);
		}

		if (typeof data === "object" && data !== null && !Array.isArray(data)) {
			return formatKeyValue(data as Record<string, unknown>);
		}

		if (
			typeof data === "string" ||
			typeof data === "number" ||
			typeof data === "boolean" ||
			data === null
		) {
			return colorizeJson(JSON.stringify(data, null, 2));
		}

		return String(data);
	}
}

function formatTable(rows: Record<string, unknown>[]): string {
	const first = rows[0] as Record<string, unknown>;
	const keys = Object.keys(first);
	const cells = rows.map((r) => keys.map((k) => colorizeCell(r[k])));
	const rawLens = rows.map((r) => keys.map((k) => String(r[k] ?? "").length));
	const widths = keys.map((k, i) => Math.max(k.length, ...rawLens.map((r) => r[i] ?? 0)));

	const header = keys.map((k, i) => colors.header(k.padEnd(widths[i] ?? 0))).join("  ");
	const separator = colors.separator(widths.map((w) => "─".repeat(w)).join("──"));
	const body = cells
		.map((row) => row.map((c, i) => padCell(c, widths[i] ?? 0)).join("  "))
		.join("\n");

	return `${header}\n${separator}\n${body}`;
}

function formatSubTable(arr: Record<string, unknown>[], indent: string): string {
	const first = arr[0] as Record<string, unknown>;
	const keys = Object.keys(first);
	const widths = keys.map((k) => Math.max(k.length, ...arr.map((r) => String(r[k] ?? "").length)));

	const header = indent + keys.map((k, i) => colors.header(k.padEnd(widths[i] ?? 0))).join("  ");
	const sep = indent + colors.separator(widths.map((w) => "─".repeat(w)).join("──"));
	const body = arr
		.map((r) => indent + keys.map((k, i) => padCell(colorizeCell(r[k]), widths[i] ?? 0)).join("  "))
		.join("\n");

	return `${header}\n${sep}\n${body}`;
}

function formatKeyValue(obj: Record<string, unknown>): string {
	const entries = Object.entries(obj);
	if (entries.length === 0) return "";
	const maxKey = Math.max(...entries.map(([k]) => k.length));
	return entries
		.map(([k, v]) => {
			if (Array.isArray(v) && v.length > 0 && typeof v[0] === "object" && v[0] !== null) {
				const label = colors.label(k.padEnd(maxKey));
				return `${label}\n${formatSubTable(v as Record<string, unknown>[], "  ")}`;
			}
			const val = typeof v === "object" && v !== null ? JSON.stringify(v) : colorizeCell(v);
			return `${colors.label(k.padEnd(maxKey))}  ${val}`;
		})
		.join("\n");
}
