import {
	Badge,
	Button,
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
	Tooltip,
	TooltipPopup,
	TooltipTrigger,
} from "@oidfed/ui";
import { Download, Key, ShieldCheck, ShieldX } from "lucide-react";
import { useHistoricalKeys } from "../hooks/use-historical-keys";

interface HistoricalKeysProps {
	readonly endpoint?: string | undefined;
	readonly issuerJwks?: { keys: readonly Record<string, unknown>[] } | undefined;
}

function formatDate(epoch: number): string {
	return new Date(epoch * 1000).toISOString().replace("T", " ").slice(0, 19);
}

function getKeyStatus(key: {
	exp: number;
	nbf?: number | undefined;
	revoked?: { revoked_at: number; reason?: string | undefined } | undefined;
}): { label: string; variant: "success" | "warning" | "error" | "outline" } {
	const now = Math.floor(Date.now() / 1000);
	if (key.revoked) return { label: "Revoked", variant: "error" };
	if (key.nbf != null && key.nbf > now) return { label: "Not yet valid", variant: "outline" };
	if (key.exp <= now) return { label: "Expired", variant: "warning" };
	return { label: "Active", variant: "success" };
}

export function HistoricalKeys({ endpoint, issuerJwks }: HistoricalKeysProps) {
	const {
		keys,
		loading,
		error,
		signatureValid,
		fetch: fetchKeys,
	} = useHistoricalKeys(endpoint, issuerJwks);

	if (!endpoint) return null;

	const sortedKeys = keys ? [...keys].sort((a, b) => b.exp - a.exp) : null;

	return (
		<Card>
			<CardHeader>
				<CardTitle className="flex items-center gap-2 text-sm">
					<Key className="size-4" />
					Historical Keys
				</CardTitle>
			</CardHeader>
			<CardContent className="space-y-3">
				<div className="flex items-center gap-2 flex-wrap">
					<span className="text-muted-foreground font-mono text-xs truncate max-w-[400px]">
						{endpoint}
					</span>
					<Button variant="outline" size="sm" onClick={fetchKeys} disabled={loading}>
						<Download className="size-3.5 mr-1" />
						{loading ? "Fetching…" : "Fetch Historical Keys"}
					</Button>
				</div>

				{signatureValid != null && (
					<div className="flex items-center gap-1.5">
						{signatureValid ? (
							<>
								<ShieldCheck className="size-4 text-success-foreground" />
								<Badge variant="success" size="sm">
									Signature valid
								</Badge>
							</>
						) : (
							<>
								<ShieldX className="size-4 text-destructive" />
								<Badge variant="error" size="sm">
									Signature invalid
								</Badge>
							</>
						)}
					</div>
				)}

				{error && <p className="text-sm text-destructive">{error}</p>}

				{sortedKeys && sortedKeys.length > 0 && (
					<div className="rounded-lg border">
						<Table>
							<TableHeader>
								<TableRow>
									<TableHead>kid</TableHead>
									<TableHead>kty</TableHead>
									<TableHead>alg</TableHead>
									<TableHead>use</TableHead>
									<TableHead>iat</TableHead>
									<TableHead>exp</TableHead>
									<TableHead>Status</TableHead>
								</TableRow>
							</TableHeader>
							<TableBody>
								{sortedKeys.map((key) => {
									const status = getKeyStatus(key);
									return (
										<TableRow
											key={key.kid}
											className={key.revoked ? "line-through opacity-60" : ""}
										>
											<TableCell className="font-mono text-xs">{key.kid}</TableCell>
											<TableCell>
												<Badge variant="outline">{key.kty}</Badge>
											</TableCell>
											<TableCell className="font-mono text-xs">{key.alg ?? "—"}</TableCell>
											<TableCell>{key.use ?? "—"}</TableCell>
											<TableCell className="font-mono text-xs">
												{key.iat != null ? formatDate(key.iat) : "—"}
											</TableCell>
											<TableCell className="font-mono text-xs">{formatDate(key.exp)}</TableCell>
											<TableCell>
												{key.revoked?.reason ? (
													<Tooltip>
														<TooltipTrigger
															render={
																<Badge variant={status.variant} size="sm">
																	{status.label}
																</Badge>
															}
														/>
														<TooltipPopup>{key.revoked.reason}</TooltipPopup>
													</Tooltip>
												) : (
													<Badge variant={status.variant} size="sm">
														{status.label}
													</Badge>
												)}
											</TableCell>
										</TableRow>
									);
								})}
							</TableBody>
						</Table>
					</div>
				)}

				{sortedKeys && sortedKeys.length === 0 && (
					<p className="text-sm text-muted-foreground">No historical keys returned.</p>
				)}
			</CardContent>
		</Card>
	);
}
