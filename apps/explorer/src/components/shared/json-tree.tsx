import JsonView from "@uiw/react-json-view";
import { darkTheme } from "@uiw/react-json-view/dark";
import { lightTheme } from "@uiw/react-json-view/light";
import { useSettings } from "@/hooks/use-settings";

interface JsonTreeProps {
	readonly data: unknown;
	readonly collapsed?: number;
	readonly className?: string;
}

export function JsonTree({ data, collapsed = 2, className }: JsonTreeProps) {
	const [settings] = useSettings();
	const isDark =
		settings.theme === "dark" ||
		(settings.theme === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);

	return (
		<div className={`rounded-lg border bg-code p-4 overflow-auto ${className ?? ""}`}>
			<JsonView
				value={data as object}
				collapsed={collapsed}
				indentWidth={settings.jsonIndent}
				style={isDark ? darkTheme : lightTheme}
				displayDataTypes={false}
			/>
		</div>
	);
}
