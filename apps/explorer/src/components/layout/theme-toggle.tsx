import { Button, Tooltip, TooltipPopup, TooltipTrigger } from "@oidfed/ui";
import { Monitor, Moon, Sun } from "lucide-react";
import { useTheme } from "@/hooks/use-theme";

const icons = {
	light: Sun,
	dark: Moon,
	system: Monitor,
} as const;

export function ThemeToggle() {
	const [theme, cycle] = useTheme();
	const Icon = icons[theme];

	return (
		<Tooltip>
			<TooltipTrigger
				render={<Button variant="ghost" size="icon" onClick={cycle} aria-label="Toggle theme" />}
			>
				<Icon className="size-4" />
			</TooltipTrigger>
			<TooltipPopup>Theme: {theme}</TooltipPopup>
		</Tooltip>
	);
}
