import {
	Accordion,
	AccordionContent,
	AccordionItem,
	AccordionTrigger,
	Badge,
	Button,
	Card,
	CardContent,
	CardHeader,
	CardTitle,
} from "@oidfed/ui";
import { ShieldCheck } from "lucide-react";
import { JwtViewer } from "@/components/shared/jwt-viewer";
import { useTrustMarkValidation } from "../hooks/use-trust-mark-validation";

interface TrustMark {
	readonly trust_mark_type: string;
	readonly trust_mark: string;
}

interface TrustMarksPanelProps {
	readonly trustMarks: readonly TrustMark[];
}

function decodeTrustMarkPayload(jwt: string): Record<string, unknown> | null {
	try {
		const parts = jwt.split(".");
		if (parts.length !== 3 || !parts[1]) return null;
		return JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/"))) as Record<
			string,
			unknown
		>;
	} catch {
		return null;
	}
}

function formatDate(epoch: unknown): string | null {
	if (typeof epoch !== "number") return null;
	return new Date(epoch * 1000).toISOString().replace("T", " ").slice(0, 19);
}

const statusBadgeMap = {
	valid: { label: "Valid", variant: "success" as const },
	expired: { label: "Expired", variant: "warning" as const },
	invalid: { label: "Invalid", variant: "error" as const },
	error: { label: "Error", variant: "error" as const },
	idle: { label: "Unverified", variant: "outline" as const },
	verifying: { label: "Verifying…", variant: "outline" as const },
} as const;

function TrustMarkItem({ tm }: { readonly tm: TrustMark }) {
	const payload = decodeTrustMarkPayload(tm.trust_mark);
	const { status, details, error, verify } = useTrustMarkValidation(tm.trust_mark);
	const badge = statusBadgeMap[status];

	return (
		<AccordionItem key={tm.trust_mark_type}>
			<AccordionTrigger className="text-sm">
				<div className="flex items-center gap-2">
					<Badge variant="outline">{tm.trust_mark_type}</Badge>
					{payload?.iss != null && (
						<span className="text-xs text-muted-foreground font-mono truncate max-w-[300px]">
							iss: {String(payload.iss)}
						</span>
					)}
					<Badge variant={badge.variant} size="sm">
						{badge.label}
					</Badge>
				</div>
			</AccordionTrigger>
			<AccordionContent>
				<div className="space-y-3">
					<div className="flex items-center gap-2">
						{status === "idle" && (
							<Button variant="ghost" size="sm" onClick={verify}>
								Verify
							</Button>
						)}
						{status === "verifying" && (
							<Button variant="ghost" size="sm" disabled>
								Verifying…
							</Button>
						)}
						{(status === "valid" ||
							status === "expired" ||
							status === "invalid" ||
							status === "error") && (
							<Button variant="ghost" size="sm" onClick={verify}>
								Re-verify
							</Button>
						)}
					</div>

					{error && <p className="text-sm text-destructive">{error}</p>}

					{details && (
						<div className="rounded-lg border p-3 space-y-1 text-xs">
							<div>
								<span className="text-muted-foreground">sub: </span>
								<span className="font-mono">{details.subject}</span>
							</div>
							<div>
								<span className="text-muted-foreground">iat: </span>
								<span className="font-mono">{formatDate(details.issuedAt) ?? "—"}</span>
							</div>
							{details.expiresAt != null && (
								<div>
									<span className="text-muted-foreground">exp: </span>
									<span className="font-mono">{formatDate(details.expiresAt) ?? "—"}</span>
								</div>
							)}
							{details.delegation && (
								<div className="mt-2 pt-2 border-t">
									<span className="text-muted-foreground">Delegation: </span>
									<span className="font-mono">
										{details.delegation.issuer} → {details.delegation.subject}
									</span>
								</div>
							)}
						</div>
					)}

					<JwtViewer jwt={tm.trust_mark} contentType="application/trust-mark+jwt" />
				</div>
			</AccordionContent>
		</AccordionItem>
	);
}

export function TrustMarksPanel({ trustMarks }: TrustMarksPanelProps) {
	if (trustMarks.length === 0) {
		return <p className="text-sm text-muted-foreground">No trust marks present.</p>;
	}

	return (
		<Card>
			<CardHeader>
				<CardTitle className="flex items-center gap-2 text-sm">
					<ShieldCheck className="size-4" />
					Trust Marks ({trustMarks.length})
				</CardTitle>
			</CardHeader>
			<CardContent>
				<Accordion>
					{trustMarks.map((tm, i) => (
						<TrustMarkItem key={tm.trust_mark_type ?? i} tm={tm} />
					))}
				</Accordion>
			</CardContent>
		</Card>
	);
}
