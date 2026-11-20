import ReactDiffViewer from "react-diff-viewer-continued";
import { useSettings } from "@/hooks/use-settings";

interface ResolvedMetadataDiffProps {
	readonly originalMetadata: Record<string, unknown>;
	readonly resolvedMetadata: Record<string, Record<string, unknown>>;
	readonly leftTitle?: string | undefined;
	readonly rightTitle?: string | undefined;
}

export function ResolvedMetadataDiff({
	originalMetadata,
	resolvedMetadata,
	leftTitle = "Original Metadata",
	rightTitle = "Resolved Metadata",
}: ResolvedMetadataDiffProps) {
	const [settings] = useSettings();
	const isDark =
		settings.theme === "dark" ||
		(settings.theme === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);

	const original = JSON.stringify(originalMetadata, null, 2);
	const resolved = JSON.stringify(resolvedMetadata, null, 2);

	if (original === resolved) {
		return (
			<p className="text-sm text-muted-foreground">No metadata changes after policy application.</p>
		);
	}

	return (
		<div className="rounded-lg border overflow-hidden">
			<ReactDiffViewer
				oldValue={original}
				newValue={resolved}
				splitView
				leftTitle={leftTitle}
				rightTitle={rightTitle}
				useDarkTheme={isDark}
			/>
		</div>
	);
}
