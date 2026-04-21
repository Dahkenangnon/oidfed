import { renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useTheme } from "@/hooks/use-theme";

// Mock useSettings
const mockUpdate = vi.fn();
let currentTheme = "light" as "light" | "dark" | "system";

vi.mock("@/hooks/use-settings", () => ({
	useSettings: () =>
		[
			{ theme: currentTheme, httpTimeoutMs: 5000, maxChainDepth: 10 },
			(patch: Record<string, unknown>) => {
				currentTheme = patch.theme as "light" | "dark" | "system";
				mockUpdate(patch);
			},
		] as const,
}));

describe("useTheme", () => {
	afterEach(() => {
		currentTheme = "light";
		document.documentElement.classList.remove("dark");
		mockUpdate.mockClear();
	});

	it("applies dark class when theme is dark", () => {
		currentTheme = "dark";
		renderHook(() => useTheme());
		expect(document.documentElement.classList.contains("dark")).toBe(true);
	});

	it("removes dark class when theme is light", () => {
		document.documentElement.classList.add("dark");
		currentTheme = "light";
		renderHook(() => useTheme());
		expect(document.documentElement.classList.contains("dark")).toBe(false);
	});

	it("persists theme to cookie on change", () => {
		currentTheme = "dark";
		renderHook(() => useTheme());
		expect(document.cookie).toContain("oidfed_theme=dark");
	});
});
