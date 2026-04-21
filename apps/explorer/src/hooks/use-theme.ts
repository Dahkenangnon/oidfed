import { useCallback, useEffect } from "react";
import type { Theme } from "@/types";
import { useSettings } from "./use-settings";

const COOKIE_NAME = "oidfed_theme";
const COOKIE_MAX_AGE = 60 * 60 * 24 * 365; // 1 year

function setThemeCookie(theme: Theme): void {
	// biome-ignore lint/suspicious/noDocumentCookie: Cookie Store API not universally supported
	document.cookie = `${COOKIE_NAME}=${encodeURIComponent(theme)};path=/;max-age=${COOKIE_MAX_AGE};SameSite=Lax`;
}

export function useTheme(): readonly [Theme, () => void] {
	const [settings, update] = useSettings();
	const theme = settings.theme;

	useEffect(() => {
		// Sync cookie whenever theme changes
		setThemeCookie(theme);

		const root = document.documentElement;
		if (theme === "system") {
			const mq = window.matchMedia("(prefers-color-scheme: dark)");
			root.classList.toggle("dark", mq.matches);
			const handler = (e: MediaQueryListEvent) => root.classList.toggle("dark", e.matches);
			mq.addEventListener("change", handler);
			return () => mq.removeEventListener("change", handler);
		}
		root.classList.toggle("dark", theme === "dark");
	}, [theme]);

	const cycle = useCallback(() => {
		const order: Theme[] = ["light", "dark", "system"];
		const next = order[(order.indexOf(theme) + 1) % order.length] ?? "system";
		update({ theme: next });
	}, [theme, update]);

	return [theme, cycle] as const;
}
