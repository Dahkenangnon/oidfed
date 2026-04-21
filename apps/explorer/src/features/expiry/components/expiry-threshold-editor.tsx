import { Button, Collapsible, CollapsibleContent, Input } from "@oidfed/ui";
import { RotateCcw } from "lucide-react";
import { useState } from "react";
import { useSettings } from "@/hooks/use-settings";

const DEFAULT_CRITICAL = 7;
const DEFAULT_WARNING = 30;
const DEFAULT_SOON = 90;

interface ExpiryThresholdEditorProps {
	readonly open: boolean;
	readonly onOpenChange: (open: boolean) => void;
}

export function ExpiryThresholdEditor({ open, onOpenChange }: ExpiryThresholdEditorProps) {
	const [settings, updateSettings] = useSettings();
	const current = settings.expirationWarningDays;

	const [critical, setCritical] = useState(current[0] ?? 7);
	const [warning, setWarning] = useState(current[1] ?? 30);
	const [soon, setSoon] = useState(current[2] ?? 90);

	const handleApply = () => {
		updateSettings({ expirationWarningDays: [critical, warning, soon] });
	};

	const handleDefaults = () => {
		setCritical(DEFAULT_CRITICAL);
		setWarning(DEFAULT_WARNING);
		setSoon(DEFAULT_SOON);
		updateSettings({ expirationWarningDays: [DEFAULT_CRITICAL, DEFAULT_WARNING, DEFAULT_SOON] });
	};

	const isDirty =
		critical !== (current[0] ?? 7) || warning !== (current[1] ?? 30) || soon !== (current[2] ?? 90);

	return (
		<Collapsible open={open} onOpenChange={onOpenChange}>
			<CollapsibleContent>
				<div className="rounded-lg border p-4 space-y-4">
					<h4 className="text-sm font-medium">Expiry Warning Thresholds</h4>
					<div className="grid grid-cols-3 gap-4">
						<div className="space-y-1">
							<label className="text-xs text-muted-foreground">Critical (days)</label>
							<Input
								type="number"
								min={1}
								value={critical}
								onChange={(e) => setCritical(Number(e.target.value))}
								className="h-8 text-sm"
							/>
						</div>
						<div className="space-y-1">
							<label className="text-xs text-muted-foreground">Warning (days)</label>
							<Input
								type="number"
								min={1}
								value={warning}
								onChange={(e) => setWarning(Number(e.target.value))}
								className="h-8 text-sm"
							/>
						</div>
						<div className="space-y-1">
							<label className="text-xs text-muted-foreground">Soon (days)</label>
							<Input
								type="number"
								min={1}
								value={soon}
								onChange={(e) => setSoon(Number(e.target.value))}
								className="h-8 text-sm"
							/>
						</div>
					</div>
					<div className="flex items-center gap-2">
						<Button size="sm" onClick={handleApply} disabled={!isDirty}>
							Apply
						</Button>
						<Button variant="outline" size="sm" onClick={handleDefaults}>
							<RotateCcw className="mr-1.5 size-3" />
							Defaults
						</Button>
					</div>
				</div>
			</CollapsibleContent>
		</Collapsible>
	);
}
