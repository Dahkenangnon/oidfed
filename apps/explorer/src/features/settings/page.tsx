import {
	Alert,
	AlertDescription,
	Button,
	Card,
	CardContent,
	CardHeader,
	CardTitle,
	Input,
	Label,
} from "@oidfed/ui";
import {
	AlertTriangle,
	ArrowDownUp,
	Download,
	Palette,
	Plus,
	Shield,
	Trash2,
	Upload,
	Wifi,
} from "lucide-react";
import { useState } from "react";
import { usePageTitle } from "@/hooks/use-page-title";
import { useSettings } from "@/hooks/use-settings";
import { useTheme } from "@/hooks/use-theme";
import { downloadJson } from "@/lib/export";
import { SettingsSchema } from "@/lib/settings";

export function SettingsPage() {
	usePageTitle("Settings — OidFed Explorer");
	const [settings, update] = useSettings();
	const [theme, _cycleTheme] = useTheme();
	const [newAnchorUrl, setNewAnchorUrl] = useState("");
	const [importError, setImportError] = useState<string | null>(null);

	const addTrustAnchor = () => {
		const trimmed = newAnchorUrl.trim();
		if (!trimmed) return;
		try {
			new URL(trimmed);
		} catch {
			return;
		}
		update({
			trustAnchors: [...settings.trustAnchors, { entityId: trimmed }],
		});
		setNewAnchorUrl("");
	};

	const removeTrustAnchor = (index: number) => {
		update({
			trustAnchors: settings.trustAnchors.filter((_: unknown, i: number) => i !== index),
		});
	};

	const handleExport = () => {
		downloadJson(settings, "oidfed-explorer-settings.json");
	};

	const handleImport = () => {
		const input = document.createElement("input");
		input.type = "file";
		input.accept = ".json";
		input.onchange = async () => {
			const file = input.files?.[0];
			if (!file) return;
			try {
				const text = await file.text();
				const parsed = SettingsSchema.parse(JSON.parse(text));
				update(parsed);
			} catch {
				setImportError("Invalid settings file. Please check the format and try again.");
			}
		};
		input.click();
	};

	return (
		<div className="space-y-6">
			<div className="space-y-1">
				<div className="h-1 w-8 rounded-full bg-brand-500" />
				<h1 className="text-2xl font-semibold tracking-tight">Settings</h1>
				<p className="text-sm text-muted-foreground">Configure the OIDFED Explorer</p>
			</div>

			{/* Theme */}
			<Card>
				<CardHeader>
					<CardTitle className="flex items-center gap-2 text-sm">
						<Palette className="size-4 text-brand-500" />
						Appearance
					</CardTitle>
					<p className="text-xs text-muted-foreground">Customize the look and feel</p>
				</CardHeader>
				<CardContent className="space-y-4">
					<div className="flex items-center justify-between">
						<Label>Theme</Label>
						<div className="flex gap-0.5 rounded-lg bg-muted p-0.5">
							{(["light", "dark", "system"] as const).map((t) => (
								<Button
									key={t}
									variant="ghost"
									size="sm"
									className={
										theme === t ? "bg-brand-500 text-white hover:bg-brand-600 hover:text-white" : ""
									}
									onClick={() => update({ theme: t })}
								>
									{t.charAt(0).toUpperCase() + t.slice(1)}
								</Button>
							))}
						</div>
					</div>
					<div className="flex items-center justify-between">
						<Label>JSON indent</Label>
						<Input
							type="number"
							min={1}
							max={8}
							value={settings.jsonIndent}
							onChange={(e) => update({ jsonIndent: Number(e.target.value) })}
							className="w-20"
						/>
					</div>
				</CardContent>
			</Card>

			{/* Trust Anchors */}
			<Card>
				<CardHeader>
					<CardTitle className="flex items-center gap-2 text-sm">
						<Shield className="size-4 text-brand-500" />
						Trust Anchors
					</CardTitle>
					<p className="text-xs text-muted-foreground">Configure trusted federation authorities</p>
				</CardHeader>
				<CardContent className="space-y-4">
					{settings.trustAnchors.length > 0 ? (
						<ul className="space-y-2">
							{settings.trustAnchors.map((anchor, i) => (
								<li
									key={anchor.entityId}
									className="flex items-center gap-2 rounded-md px-2 py-1 hover:bg-muted/50 transition-colors"
								>
									<span className="text-xs text-muted-foreground w-4">{i + 1}.</span>
									<span className="flex-1 font-mono text-sm truncate">{anchor.entityId}</span>
									<Button variant="ghost" size="icon" onClick={() => removeTrustAnchor(i)}>
										<Trash2 className="size-4 text-destructive" />
									</Button>
								</li>
							))}
						</ul>
					) : (
						<div className="flex flex-col items-center gap-2 rounded-lg border border-dashed py-6 text-muted-foreground">
							<Shield className="size-8 opacity-30" />
							<p className="text-sm">No trust anchors configured</p>
						</div>
					)}
					<div className="flex gap-2">
						<Input
							placeholder="https://trust-anchor.example.com"
							value={newAnchorUrl}
							onChange={(e) => setNewAnchorUrl(e.target.value)}
							onKeyDown={(e) => {
								if (e.key === "Enter") {
									e.preventDefault();
									addTrustAnchor();
								}
							}}
						/>
						<Button onClick={addTrustAnchor} disabled={!newAnchorUrl.trim()}>
							<Plus className="mr-2 size-4" />
							Add
						</Button>
					</div>
				</CardContent>
			</Card>

			{/* HTTP Settings */}
			<Card>
				<CardHeader>
					<CardTitle className="flex items-center gap-2 text-sm">
						<Wifi className="size-4 text-brand-500" />
						Network
					</CardTitle>
					<p className="text-xs text-muted-foreground">Adjust HTTP and chain resolution settings</p>
				</CardHeader>
				<CardContent className="space-y-4">
					<div className="flex items-center justify-between">
						<Label>HTTP Timeout (ms)</Label>
						<Input
							type="number"
							min={1000}
							max={60000}
							step={1000}
							value={settings.httpTimeoutMs}
							onChange={(e) => update({ httpTimeoutMs: Number(e.target.value) })}
							className="w-28"
						/>
					</div>
					<p className="text-xs text-muted-foreground -mt-2">
						Time before a fetch request is aborted (1000–60000)
					</p>
					<div className="flex items-center justify-between">
						<Label>Max chain depth</Label>
						<Input
							type="number"
							min={1}
							max={50}
							value={settings.maxChainDepth}
							onChange={(e) => update({ maxChainDepth: Number(e.target.value) })}
							className="w-20"
						/>
					</div>
					<p className="text-xs text-muted-foreground -mt-2">
						Maximum number of hops when resolving trust chains (1–50)
					</p>
				</CardContent>
			</Card>

			{/* Import/Export */}
			<Card>
				<CardHeader>
					<CardTitle className="flex items-center gap-2 text-sm">
						<ArrowDownUp className="size-4 text-brand-500" />
						Import / Export
					</CardTitle>
					<p className="text-xs text-muted-foreground">Backup or restore your configuration</p>
				</CardHeader>
				<CardContent className="space-y-3">
					<div className="flex gap-2">
						<Button variant="outline" onClick={handleExport}>
							<Download className="mr-2 size-4" />
							Export Settings
						</Button>
						<Button
							variant="outline"
							onClick={() => {
								setImportError(null);
								handleImport();
							}}
						>
							<Upload className="mr-2 size-4" />
							Import Settings
						</Button>
					</div>
					{importError && (
						<Alert variant="error">
							<AlertTriangle className="size-4" />
							<AlertDescription>{importError}</AlertDescription>
						</Alert>
					)}
				</CardContent>
			</Card>
		</div>
	);
}
