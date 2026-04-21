import {
	Badge,
	Card,
	CardContent,
	CardHeader,
	CardTitle,
	Table,
	TableBody,
	TableCell,
	TableHead,
	TableHeader,
	TableRow,
} from "@oidfed/ui";
import { Award } from "lucide-react";
import { EntityLink } from "@/components/shared/entity-link";

interface TrustMarkIssuersPanelProps {
	readonly trustMarkIssuers?: Record<string, string[]> | undefined;
	readonly trustMarkOwners?: Record<string, { sub: string; jwks: unknown }> | undefined;
}

export function TrustMarkIssuersPanel({
	trustMarkIssuers,
	trustMarkOwners,
}: TrustMarkIssuersPanelProps) {
	if (!trustMarkIssuers && !trustMarkOwners) return null;

	const issuerEntries = trustMarkIssuers ? Object.entries(trustMarkIssuers) : [];
	const ownerEntries = trustMarkOwners ? Object.entries(trustMarkOwners) : [];

	if (issuerEntries.length === 0 && ownerEntries.length === 0) return null;

	return (
		<Card>
			<CardHeader>
				<CardTitle className="flex items-center gap-2 text-sm">
					<Award className="size-4" />
					Trust Mark Issuers & Owners
				</CardTitle>
			</CardHeader>
			<CardContent className="space-y-4">
				{issuerEntries.length > 0 && (
					<div className="space-y-2">
						<h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
							Authorized Issuers
						</h4>
						<div className="rounded-lg border">
							<Table>
								<TableHeader>
									<TableRow>
										<TableHead>Trust Mark Type</TableHead>
										<TableHead>Authorized Issuers</TableHead>
									</TableRow>
								</TableHeader>
								<TableBody>
									{issuerEntries.map(([type, issuers]) => (
										<TableRow key={type}>
											<TableCell>
												<Badge variant="outline" className="font-mono text-xs">
													{type}
												</Badge>
											</TableCell>
											<TableCell>
												<div className="flex flex-col gap-1">
													{issuers.map((issuer) => (
														<EntityLink key={issuer} entityId={issuer} />
													))}
												</div>
											</TableCell>
										</TableRow>
									))}
								</TableBody>
							</Table>
						</div>
					</div>
				)}

				{ownerEntries.length > 0 && (
					<div className="space-y-2">
						<h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
							Trust Mark Owners
						</h4>
						<div className="rounded-lg border">
							<Table>
								<TableHeader>
									<TableRow>
										<TableHead>Trust Mark Type</TableHead>
										<TableHead>Owner</TableHead>
										<TableHead>Keys</TableHead>
									</TableRow>
								</TableHeader>
								<TableBody>
									{ownerEntries.map(([type, owner]) => {
										const jwks = owner.jwks as { keys?: unknown[] } | undefined;
										const keyCount = jwks?.keys?.length ?? 0;
										return (
											<TableRow key={type}>
												<TableCell>
													<Badge variant="outline" className="font-mono text-xs">
														{type}
													</Badge>
												</TableCell>
												<TableCell>
													<EntityLink entityId={owner.sub} />
												</TableCell>
												<TableCell>
													<Badge variant="outline" size="sm">
														{keyCount} key{keyCount !== 1 ? "s" : ""}
													</Badge>
												</TableCell>
											</TableRow>
										);
									})}
								</TableBody>
							</Table>
						</div>
					</div>
				)}
			</CardContent>
		</Card>
	);
}
