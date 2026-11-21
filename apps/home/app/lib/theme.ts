/**
 * Theme resolution shared by the pre-hydration script in `root.tsx` and the
 * `ThemeToggle` component.
 *
 * A visitor who has never used the toggle gets the theme their operating
 * system asks for, and every read of `localStorage` tolerates browsers that
 * deny access to storage — private windows and hardened profiles throw on
 * property access rather than returning `null`.
 */

export type Theme = "light" | "dark";

export const THEME_STORAGE_KEY = "theme";

/** Browser-chrome colors, mirroring the `--background` tokens in `app.css`. */
export const THEME_COLORS: Record<Theme, string> = {
	light: "#fcfdff",
	dark: "#101a24",
};

const SYSTEM_DARK_QUERY = "(prefers-color-scheme: dark)";

/** Narrows a raw storage value to a theme, rejecting anything unrecognized. */
export function parseStoredTheme(value: string | null): Theme | null {
	return value === "dark" || value === "light" ? value : null;
}

/** The theme to render, given the stored choice and the system preference. */
export function resolveTheme(stored: Theme | null, systemPrefersDark: boolean): Theme {
	if (stored) return stored;
	return systemPrefersDark ? "dark" : "light";
}

/** Reads the stored choice, reporting `null` when storage is unavailable. */
export function readStoredTheme(): Theme | null {
	try {
		return parseStoredTheme(localStorage.getItem(THEME_STORAGE_KEY));
	} catch {
		return null;
	}
}

/** Records a choice. A browser that denies storage keeps it for this page only. */
export function storeTheme(theme: Theme): void {
	try {
		localStorage.setItem(THEME_STORAGE_KEY, theme);
	} catch {
		// Nothing to recover: the toggle still applies the theme to the document.
	}
}

/** Reports whether the operating system currently asks for a dark theme. */
export function systemPrefersDark(): boolean {
	return window.matchMedia(SYSTEM_DARK_QUERY).matches;
}

/** Applies a theme to the document and keeps the browser chrome in step. */
export function applyTheme(theme: Theme): void {
	document.documentElement.classList.toggle("dark", theme === "dark");
	document
		.querySelector('meta[name="theme-color"]')
		?.setAttribute("content", THEME_COLORS[theme]);
}

/**
 * The inline script that resolves the theme before first paint, so the page
 * never flashes the wrong one. Kept to a single statement with no newlines so
 * it stays readable in the rendered document.
 */
export function themeBootstrapScript(): string {
	return `(function(){try{var s=localStorage.getItem("${THEME_STORAGE_KEY}");if(s==="dark"||(s!=="light"&&matchMedia("${SYSTEM_DARK_QUERY}").matches)){document.documentElement.classList.add("dark");var m=document.querySelector('meta[name="theme-color"]');if(m)m.setAttribute("content","${THEME_COLORS.dark}")}}catch(e){}})()`;
}
