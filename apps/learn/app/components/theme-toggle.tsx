import { Button } from "@oidfed/ui";
import { Moon, Sun } from "lucide-react";
import { useEffect, useState } from "react";

export function ThemeToggle() {
	const [dark, setDark] = useState(false);

	useEffect(() => {
		const stored = localStorage.getItem("theme");
		const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
		const isDark = stored === "dark" || (!stored && prefersDark);
		setDark(isDark);
		document.documentElement.classList.toggle("dark", isDark);
	}, []);

	function toggle() {
		const next = !dark;
		setDark(next);
		document.documentElement.classList.toggle("dark", next);
		localStorage.setItem("theme", next ? "dark" : "light");
	}

	return (
		<Button variant="ghost" size="icon" onClick={toggle} aria-label="Toggle theme">
			{dark ? <Sun className="size-4" /> : <Moon className="size-4" />}
		</Button>
	);
}
