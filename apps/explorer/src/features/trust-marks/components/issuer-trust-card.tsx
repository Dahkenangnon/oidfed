import { Badge, Card, CardContent, CardHeader, CardTitle } from "@oidfed/ui";
import { ShieldCheck, ShieldX } from "lucide-react";
import { EntityLink } from "@/components/shared/entity-link";

interface IssuerTrustCardProps {
	readonly issuerTrusted: boolean | null;
	readonly issuerChainError: string | null;
	readonly trustedByTA: string | null;
}

export function IssuerTrustCard({
	issuerTrusted,
	issuerChainError,
	trustedByTA,
}: IssuerTrustCardProps) {
	if (issuerTrusted === null && !issuerChainError) return null;

	return (
		<Card>
			<CardHeader>
				<CardTitle className="text-sm">Issuer Trust</CardTitle>
			</CardHeader>
			<CardContent className="space-y-2">
				{issuerTrusted === true && (
					<div className="flex items-center gap-2">
						<ShieldCheck className="size-4 text-success-foreground" />
						<Badge variant="success">Trusted</Badge>
						{trustedByTA && (
							<span className="text-xs text-muted-foreground">
								via <EntityLink entityId={trustedByTA} />
							</span>
						)}
					</div>
				)}
				{issuerTrusted === false && (
					<div className="space-y-1">
						<div className="flex items-center gap-2">
							<ShieldX className="size-4 text-destructive-foreground" />
							<Badge variant="destructive">Not Trusted</Badge>
						</div>
						{issuerChainError && (
							<p className="text-xs text-muted-foreground">{issuerChainError}</p>
						)}
					</div>
				)}
			</CardContent>
		</Card>
	);
}
