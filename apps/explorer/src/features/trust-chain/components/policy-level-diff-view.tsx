import { AlertTriangle } from "lucide-react";
import type { PolicyLevel } from "../hooks/use-policy-level-diff";
import { ResolvedMetadataDiff } from "./resolved-metadata-diff";

interface PolicyLevelDiffViewProps {
	readonly levels: readonly PolicyLevel[];
}

export function PolicyLevelDiffView({ levels }: PolicyLevelDiffViewProps) {
	if (levels.length <= 1) {
		return (
			<p className="text-sm text-muted-foreground">
				No subordinate statements — metadata applied as-is.
			</p>
		);
	}

	return (
		<div className="space-y-6">
			{levels.slice(1).map((level) => {
				const prev = levels[level.level - 1];
				if (!prev) return null;

				return (
					<div key={level.level} className="space-y-2">
						<div className="flex items-center gap-2">
							<h4 className="text-sm font-medium">
								Level {level.level - 1} → Level {level.level}
							</h4>
							{level.issuer && (
								<span className="text-xs text-muted-foreground font-mono truncate max-w-md">
									{level.issuer}
								</span>
							)}
						</div>

						{level.error ? (
							<div className="rounded-lg border border-destructive/50 bg-destructive/10 p-3 flex items-start gap-2">
								<AlertTriangle className="size-4 text-destructive-foreground shrink-0 mt-0.5" />
								<p className="text-sm text-destructive-foreground">{level.error}</p>
							</div>
						) : (
							<ResolvedMetadataDiff
								originalMetadata={prev.metadata}
								resolvedMetadata={level.metadata}
								leftTitle={`Level ${level.level - 1}`}
								rightTitle={`Level ${level.level}`}
							/>
						)}
					</div>
				);
			})}
		</div>
	);
}
