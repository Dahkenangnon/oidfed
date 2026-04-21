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

function colorizeJson(json: string): string {
	return json.replace(
		/("(?:\\.|[^"\\])*")\s*(:?)|\b(true|false)\b|\bnull\b|\b(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)\b/g,
		(match, str?: string, colon?: string, bool?: string, num?: string) => {
			if (str && colon) return `${colors.key(str)}${colon}`;
			if (str) return colors.string(str);
			if (bool) return colors.boolean(match);
			if (num) return colors.number(match);
			if (match === "null") return colors.null(match);
			return match;
		},
	);
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
