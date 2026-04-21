import { z } from "zod";

export const TrustAnchorSchema = z.object({
	entityId: z.string().url(),
	jwks: z.unknown().optional(),
});

export const SettingsSchema = z.object({
	trustAnchors: z.array(TrustAnchorSchema).default([]),
	httpTimeoutMs: z.number().min(1000).max(60000).default(10000),
	maxChainDepth: z.number().min(1).max(50).default(10),
	theme: z.enum(["light", "dark", "system"]).default("system"),
	jsonIndent: z.number().min(1).max(8).default(2),
	expirationWarningDays: z.array(z.number().positive()).default([7, 30, 90]),
});

export type Settings = z.infer<typeof SettingsSchema>;

const STORAGE_KEY = "oidfed-explorer-settings";

export function loadSettings(): Settings {
	try {
		const raw = localStorage.getItem(STORAGE_KEY);
		if (!raw) {
			return SettingsSchema.parse({});
		}
		return SettingsSchema.parse(JSON.parse(raw));
	} catch {
		return SettingsSchema.parse({});
	}
}

export function saveSettings(settings: Settings): void {
	localStorage.setItem(STORAGE_KEY, JSON.stringify(settings));
}

const RECENT_KEY = "oidfed-explorer-recent";
const MAX_RECENT = 20;

export interface RecentEntity {
	readonly entityId: string;
	readonly timestamp: number;
}

export function loadRecentEntities(): readonly RecentEntity[] {
	try {
		const raw = localStorage.getItem(RECENT_KEY);
		if (!raw) return [];
		return JSON.parse(raw) as RecentEntity[];
	} catch {
		return [];
	}
}

export function addRecentEntity(entityId: string): void {
	const recent = loadRecentEntities().filter((r) => r.entityId !== entityId);
	const updated = [{ entityId, timestamp: Date.now() }, ...recent].slice(0, MAX_RECENT);
	localStorage.setItem(RECENT_KEY, JSON.stringify(updated));
}
