import type { TrustMarkEvaluation } from "@oidfed/core";
import { Badge } from "@oidfed/ui";
import { BadgeCheck } from "lucide-react";
import { ValidationBadge } from "@/components/shared/validation-badge";

interface TrustMarkListProps {
	readonly evaluations: readonly TrustMarkEvaluation[];
}

export function TrustMarkList({ evaluations }: TrustMarkListProps) {
	if (evaluations.length === 0) {
		return (
			<p className="text-sm text-muted-foreground">
				No Trust Marks published by the chain subject.
			</p>
		);
	}

	return (
		<div className="space-y-2">
			{evaluations.map((evaluation) => {
				const tm = evaluation.status === "verified" ? evaluation.mark : undefined;
				return (
					<div
						key={`${evaluation.referenceIndex}-${evaluation.trustMarkType}`}
						className="rounded-lg border bg-card p-3 space-y-2"
					>
						<div className="flex items-center gap-2 flex-wrap">
							{tm && <BadgeCheck className="size-4 text-brand-500" />}
							<Badge variant="outline" className="font-mono text-xs">
								{evaluation.trustMarkType}
							</Badge>
							<ValidationBadge
								status={
									evaluation.status === "verified"
										? "pass"
										: evaluation.status === "invalid"
											? "fail"
											: "pending"
								}
								label={
									evaluation.status === "verified"
										? "Verified"
										: evaluation.status === "invalid"
											? "Invalid"
											: "Unevaluated"
								}
							/>
						</div>
						{tm ? (
							<div className="text-xs text-muted-foreground space-y-1">
								<div>
									Issuer: <span className="font-mono">{tm.issuer}</span>
								</div>
								<div>
									Subject: <span className="font-mono">{tm.subject}</span>
								</div>
								<div>Issued: {new Date(tm.issuedAt * 1000).toISOString()}</div>
								{tm.expiresAt !== undefined && (
									<div>Expires: {new Date(tm.expiresAt * 1000).toISOString()}</div>
								)}
								{tm.delegation && (
									<div>
										Delegated by: <span className="font-mono">{tm.delegation.issuer}</span>
									</div>
								)}
							</div>
						) : (
							<p className="text-xs text-muted-foreground">
								{evaluation.status === "invalid"
									? evaluation.error.description
									: evaluation.status === "unevaluated"
										? evaluation.description
										: ""}
							</p>
						)}
					</div>
				);
			})}
		</div>
	);
}
