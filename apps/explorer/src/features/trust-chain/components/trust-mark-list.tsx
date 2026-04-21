import type { ValidatedTrustMark } from "@oidfed/core";
import { Badge } from "@oidfed/ui";
import { BadgeCheck } from "lucide-react";
import { ValidationBadge } from "@/components/shared/validation-badge";

interface TrustMarkListProps {
	readonly trustMarks: readonly ValidatedTrustMark[];
}

export function TrustMarkList({ trustMarks }: TrustMarkListProps) {
	if (trustMarks.length === 0) {
		return <p className="text-sm text-muted-foreground">No trust marks in this chain.</p>;
	}

	return (
		<div className="space-y-2">
			{trustMarks.map((tm, i) => (
				<div
					// biome-ignore lint/suspicious/noArrayIndexKey: trust marks may share the same type
					key={`tm-${i}-${tm.trustMarkType}`}
					className="rounded-lg border bg-card p-3 space-y-2"
				>
					<div className="flex items-center gap-2 flex-wrap">
						<BadgeCheck className="size-4 text-brand-500" />
						<Badge variant="outline" className="font-mono text-xs">
							{tm.trustMarkType}
						</Badge>
						<ValidationBadge status="pass" label="Validated" />
					</div>
					<div className="text-xs text-muted-foreground space-y-1">
						<div>
							Issuer: <span className="font-mono">{tm.issuer}</span>
						</div>
						<div>
							Subject: <span className="font-mono">{tm.subject}</span>
						</div>
						<div>Issued: {new Date(tm.issuedAt * 1000).toISOString()}</div>
						{tm.expiresAt && <div>Expires: {new Date(tm.expiresAt * 1000).toISOString()}</div>}
						{tm.delegation && (
							<div>
								Delegated by: <span className="font-mono">{tm.delegation.issuer}</span>
							</div>
						)}
					</div>
				</div>
			))}
		</div>
	);
}
