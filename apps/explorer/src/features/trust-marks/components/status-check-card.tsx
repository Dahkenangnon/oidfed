import { Badge, Button, Card, CardContent, CardHeader, CardTitle } from "@oidfed/ui";
import { RefreshCw } from "lucide-react";
import { useTrustMarkStatus } from "../hooks/use-trust-mark-status";

interface StatusCheckCardProps {
	readonly issuerEntityId: string;
	readonly trustMarkJwt: string;
}

export function StatusCheckCard({ issuerEntityId, trustMarkJwt }: StatusCheckCardProps) {
	const { result, loading, error, check } = useTrustMarkStatus();

	return (
		<Card>
			<CardHeader>
				<CardTitle className="text-sm">Live Status Check</CardTitle>
			</CardHeader>
			<CardContent className="space-y-3">
				<Button
					variant="outline"
					size="sm"
					loading={loading}
					onClick={() => check(issuerEntityId, trustMarkJwt)}
				>
					<RefreshCw className="mr-2 size-3.5" />
					Check Live Status
				</Button>

				{result && (
					<div className="flex items-center gap-2">
						<Badge variant={result.active ? "success" : "destructive"}>
							{result.active ? "Active" : "Inactive"}
						</Badge>
						<span className="text-xs text-muted-foreground">Status: {result.rawStatus}</span>
					</div>
				)}

				{error && <p className="text-xs text-destructive">{error}</p>}
			</CardContent>
		</Card>
	);
}
