import { renderHook } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { usePageTitle } from "@/hooks/use-page-title";

describe("usePageTitle", () => {
	it("sets document.title on mount", () => {
		renderHook(() => usePageTitle("Test Page"));
		expect(document.title).toBe("Test Page");
	});

	it("restores default title on unmount", () => {
		const { unmount } = renderHook(() => usePageTitle("Custom Title"));
		expect(document.title).toBe("Custom Title");
		unmount();
		expect(document.title).toBe("OidFed Explorer");
	});
});
