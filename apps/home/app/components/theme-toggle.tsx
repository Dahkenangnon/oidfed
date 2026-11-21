import { Button } from "@oidfed/ui";
import { Moon, Sun } from "lucide-react";
import { useEffect, useState } from "react";
import {
	applyTheme,
	readStoredTheme,
	resolveTheme,
	storeTheme,
	systemPrefersDark,
} from "../lib/theme";

export function ThemeToggle() {
	const [dark, setDark] = useState(false);

	useEffect(() => {
		const sync = (isDark: boolean) => {
			setDark(isDark);
			applyTheme(isDark ? "dark" : "light");
		};
		sync(resolveTheme(readStoredTheme(), systemPrefersDark()) === "dark");

		// Follow the operating system for as long as the visitor has expressed
		// no preference of their own.
		const query = window.matchMedia("(prefers-color-scheme: dark)");
		const onSystemChange = (event: MediaQueryListEvent) => {
			if (readStoredTheme() === null) sync(event.matches);
		};
		query.addEventListener("change", onSystemChange);
		return () => query.removeEventListener("change", onSystemChange);
	}, []);

	function toggle() {
		const next = dark ? "light" : "dark";
		setDark(next === "dark");
		applyTheme(next);
		storeTheme(next);
	}

	return (
		<Button variant="ghost" size="icon" onClick={toggle} aria-label="Toggle theme">
			{dark ? <Sun className="size-4" /> : <Moon className="size-4" />}
		</Button>
	);
}
