import { Button } from "@oidfed/ui";
import { AlertTriangle } from "lucide-react";
import { useNavigate } from "react-router";

interface FailedAnchor {
	readonly entityId: string;
	readonly reason: "fetch-failed" | "decode-failed" | "no-jwks" | "invalid-id";
}

interface NoTrustAnchorsWarningProps {
	readonly anchorsWithoutJwks?: readonly string[] | undefined;
	readonly failedAnchors?: readonly FailedAnchor[] | undefined;
}

const REASON_LABELS: Record<FailedAnchor["reason"], string> = {
	"fetch-failed": "unreachable (TLS/network error)",
	"decode-failed": "invalid JWT",
	"no-jwks": "no JWKS in entity configuration",
	"invalid-id": "invalid entity ID",
};

export function NoTrustAnchorsWarning({
	anchorsWithoutJwks,
	failedAnchors,
}: NoTrustAnchorsWarningProps) {
	const navigate = useNavigate();

	const hasFetchFailures = failedAnchors?.some((f) => f.reason === "fetch-failed");

	return (
		<div className="rounded-lg border border-warning/50 bg-warning/10 p-4">
			<div className="flex items-start gap-3">
				<AlertTriangle className="size-5 text-warning-foreground shrink-0 mt-0.5" />
				<div className="space-y-2">
					<p className="text-sm font-medium text-warning-foreground">
						No trust anchors with JWKS configured
					</p>
					<p className="text-sm text-warning-foreground/80">
						Trust chain resolution requires at least one trust anchor with a JWKS. Configure trust
						anchors in Settings.
					</p>
					{failedAnchors && failedAnchors.length > 0 ? (
						<ul className="text-xs text-warning-foreground/70 space-y-0.5">
							{failedAnchors.map((f) => (
								<li key={f.entityId} className="font-mono">
									<span className="opacity-80">{f.entityId}</span>
									<span className="ml-2 opacity-60">— {REASON_LABELS[f.reason]}</span>
								</li>
							))}
						</ul>
					) : anchorsWithoutJwks && anchorsWithoutJwks.length > 0 ? (
						<p className="text-xs text-warning-foreground/70">
							{anchorsWithoutJwks.length} anchor(s) configured without JWKS:{" "}
							{anchorsWithoutJwks.join(", ")}
						</p>
					) : null}
					{hasFetchFailures && (
						<p className="text-xs text-warning-foreground/70">
							Fetch failures are typically caused by an unreachable host, an untrusted TLS
							certificate, or a CORS policy blocking the request.
						</p>
					)}
					<Button variant="outline" size="sm" onClick={() => navigate("/settings")}>
						Go to Settings
					</Button>
				</div>
			</div>
		</div>
	);
}
