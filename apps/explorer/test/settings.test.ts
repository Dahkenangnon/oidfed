import { beforeEach, describe, expect, it } from "vitest";
import {
	addRecentEntity,
	loadRecentEntities,
	loadSettings,
	SettingsSchema,
	saveSettings,
} from "@/lib/settings";

describe("SettingsSchema", () => {
	it("parses empty object with defaults", () => {
		const result = SettingsSchema.parse({});
		expect(result.theme).toBe("system");
		expect(result.httpTimeoutMs).toBe(10000);
		expect(result.maxChainDepth).toBe(10);
		expect(result.jsonIndent).toBe(2);
		expect(result.trustAnchors).toEqual([]);
		expect(result.expirationWarningDays).toEqual([7, 30, 90]);
	});

	it("validates custom values", () => {
		const result = SettingsSchema.parse({
			theme: "dark",
			httpTimeoutMs: 5000,
			maxChainDepth: 5,
			trustAnchors: [{ entityId: "https://ta.example.com" }],
		});
		expect(result.theme).toBe("dark");
		expect(result.httpTimeoutMs).toBe(5000);
		expect(result.trustAnchors).toHaveLength(1);
	});

	it("rejects invalid theme", () => {
		expect(() => SettingsSchema.parse({ theme: "neon" })).toThrow();
	});

	it("rejects timeout below minimum", () => {
		expect(() => SettingsSchema.parse({ httpTimeoutMs: 100 })).toThrow();
	});
});

describe("loadSettings / saveSettings", () => {
	beforeEach(() => {
		localStorage.clear();
	});

	it("returns defaults when nothing stored", () => {
		const settings = loadSettings();
		expect(settings.theme).toBe("system");
	});

	it("round-trips settings", () => {
		const settings = SettingsSchema.parse({ theme: "dark", httpTimeoutMs: 3000 });
		saveSettings(settings);
		const loaded = loadSettings();
		expect(loaded.theme).toBe("dark");
		expect(loaded.httpTimeoutMs).toBe(3000);
	});
});

describe("recent entities", () => {
	beforeEach(() => {
		localStorage.clear();
	});

	it("stores and loads recent entities", () => {
		addRecentEntity("https://a.example.com");
		addRecentEntity("https://b.example.com");
		const recent = loadRecentEntities();
		expect(recent).toHaveLength(2);
		expect(recent[0]?.entityId).toBe("https://b.example.com");
	});

	it("deduplicates entities", () => {
		addRecentEntity("https://a.example.com");
		addRecentEntity("https://a.example.com");
		const recent = loadRecentEntities();
		expect(recent).toHaveLength(1);
	});
});
