import type { TrustMarkDelegationPayload, TrustMarkPayload } from "@oidfed/core";
import { TrustMarkStatus } from "@oidfed/core";
import { Badge, Card, CardContent, CardHeader, CardTitle } from "@oidfed/ui";
import { EntityLink } from "@/components/shared/entity-link";
import { JwtViewer } from "@/components/shared/jwt-viewer";
import { ValidationBadge } from "@/components/shared/validation-badge";
import type { TrustMarkInspectResult } from "../hooks/use-trust-mark-inspect";
import { IssuerTrustCard } from "./issuer-trust-card";
import { StatusCheckCard } from "./status-check-card";

function relativeTime(unix: number): string {
	const diffMs = Date.now() - unix * 1000;
	const abs = Math.abs(diffMs);
	const suffix = diffMs < 0 ? "from now" : "ago";
	if (abs < 60_000) return `just now`;
	if (abs < 3_600_000) return `${Math.floor(abs / 60_000)}m ${suffix}`;
	if (abs < 86_400_000) return `${Math.floor(abs / 3_600_000)}h ${suffix}`;
	return `${Math.floor(abs / 86_400_000)}d ${suffix}`;
}

function formatTimestamp(unix: number): string {
	try {
		return `${new Date(unix * 1000).toISOString()} (${relativeTime(unix)})`;
	} catch {
		return String(unix);
	}
}

function StatusBadge({ status }: { readonly status: string }) {
	const colorMap: Record<string, string> = {
		[TrustMarkStatus.Active]: "bg-success/10 text-success-foreground border-success/20",
		[TrustMarkStatus.Expired]: "bg-warning/10 text-warning-foreground border-warning/20",
		[TrustMarkStatus.Revoked]:
			"bg-destructive/10 text-destructive-foreground border-destructive/20",
		[TrustMarkStatus.Invalid]:
			"bg-destructive/10 text-destructive-foreground border-destructive/20",
	};
	return (
		<Badge variant="outline" className={colorMap[status] ?? "bg-muted text-muted-foreground"}>
			{status}
		</Badge>
	);
}

interface TrustMarkDetailProps {
	readonly result: TrustMarkInspectResult;
	readonly jwt: string;
}

function ClaimsCard({ payload }: { readonly payload: TrustMarkPayload }) {
	return (
		<Card>
			<CardHeader>
				<CardTitle className="text-sm">Claims</CardTitle>
			</CardHeader>
			<CardContent className="space-y-2 text-sm">
				<div className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5">
					<span className="text-muted-foreground font-mono text-xs">trust_mark_type</span>
					<span className="font-mono text-xs break-all">{payload.trust_mark_type}</span>

					<span className="text-muted-foreground font-mono text-xs">iss</span>
					<EntityLink entityId={payload.iss} />

					<span className="text-muted-foreground font-mono text-xs">sub</span>
					<EntityLink entityId={payload.sub} />

					<span className="text-muted-foreground font-mono text-xs">iat</span>
					<span className="text-xs">{formatTimestamp(payload.iat)}</span>

					{payload.exp !== undefined && (
						<>
							<span className="text-muted-foreground font-mono text-xs">exp</span>
							<span className="text-xs">{formatTimestamp(payload.exp)}</span>
						</>
					)}

					{payload.ref && (
						<>
							<span className="text-muted-foreground font-mono text-xs">ref</span>
							<a
								href={payload.ref}
								target="_blank"
								rel="noopener noreferrer"
								className="text-xs text-brand-500 hover:underline break-all"
							>
								{payload.ref}
							</a>
						</>
					)}

					{payload.logo_uri && (
						<>
							<span className="text-muted-foreground font-mono text-xs">logo_uri</span>
							<div className="flex items-center gap-2">
								<img src={payload.logo_uri} alt="Trust mark logo" className="h-6 rounded" />
								<span className="text-xs text-muted-foreground break-all">{payload.logo_uri}</span>
							</div>
						</>
					)}
				</div>
			</CardContent>
		</Card>
	);
}

function VerificationCard({
	validationResult,
	validationError,
}: Pick<TrustMarkInspectResult, "validationResult" | "validationError">) {
	const status = validationResult !== null ? "pass" : validationError !== null ? "fail" : "pending";

	return (
		<Card>
			<CardHeader>
				<CardTitle className="text-sm">Signature Verification</CardTitle>
			</CardHeader>
			<CardContent className="space-y-2">
				<ValidationBadge
					status={status}
					label={validationResult !== null ? "Valid" : (validationError ?? "Unknown")}
				/>
				{validationResult && (
					<div className="text-xs text-muted-foreground space-y-0.5">
						<span className="font-mono">
							Issued at: {formatTimestamp(validationResult.issuedAt)}
						</span>
						{validationResult.expiresAt !== undefined && (
							<div>
								<span className="font-mono">
									Expires: {formatTimestamp(validationResult.expiresAt)}
								</span>
								{validationResult.expiresAt < Date.now() / 1000 && (
									<StatusBadge status={TrustMarkStatus.Expired} />
								)}
							</div>
						)}
					</div>
				)}
			</CardContent>
		</Card>
	);
}

function DelegationCard({
	delegation,
	delegationVerified,
	delegationError,
	trustMarkOwner,
}: {
	readonly delegation: TrustMarkDelegationPayload;
	readonly delegationVerified: boolean | null;
	readonly delegationError: string | null;
	readonly trustMarkOwner: { sub: string; fromTA: string } | null;
}) {
	return (
		<Card>
			<CardHeader>
				<CardTitle className="text-sm">Delegation</CardTitle>
			</CardHeader>
			<CardContent className="space-y-3 text-sm">
				<div className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5">
					<span className="text-muted-foreground font-mono text-xs">iss</span>
					<EntityLink entityId={delegation.iss} />

					<span className="text-muted-foreground font-mono text-xs">sub</span>
					<EntityLink entityId={delegation.sub} />

					<span className="text-muted-foreground font-mono text-xs">trust_mark_type</span>
					<span className="font-mono text-xs">{delegation.trust_mark_type}</span>

					<span className="text-muted-foreground font-mono text-xs">iat</span>
					<span className="text-xs">{formatTimestamp(delegation.iat)}</span>

					{delegation.exp !== undefined && (
						<>
							<span className="text-muted-foreground font-mono text-xs">exp</span>
							<span className="text-xs">{formatTimestamp(delegation.exp)}</span>
						</>
					)}
				</div>

				{delegationVerified !== null && (
					<div className="space-y-1">
						<ValidationBadge
							status={delegationVerified ? "pass" : "fail"}
							label={
								delegationVerified
									? "Delegation verified"
									: (delegationError ?? "Delegation verification failed")
							}
						/>
						{trustMarkOwner && (
							<p className="text-xs text-muted-foreground">
								Owner <span className="font-mono">{trustMarkOwner.sub}</span> from TA{" "}
								<EntityLink entityId={trustMarkOwner.fromTA} />
							</p>
						)}
					</div>
				)}
			</CardContent>
		</Card>
	);
}

export function TrustMarkDetail({ result, jwt }: TrustMarkDetailProps) {
	return (
		<div className="space-y-4">
			<ClaimsCard payload={result.payload} />
			<VerificationCard
				validationResult={result.validationResult}
				validationError={result.validationError}
			/>

			<StatusCheckCard issuerEntityId={result.payload.iss} trustMarkJwt={jwt} />

			{result.delegation && (
				<DelegationCard
					delegation={result.delegation}
					delegationVerified={result.delegationVerified}
					delegationError={result.delegationError}
					trustMarkOwner={result.trustMarkOwner}
				/>
			)}

			<IssuerTrustCard
				issuerTrusted={result.issuerTrusted}
				issuerChainError={result.issuerChainError}
				trustedByTA={result.trustedByTA}
			/>

			<Card>
				<CardHeader>
					<CardTitle className="text-sm">Raw JWT</CardTitle>
				</CardHeader>
				<CardContent>
					<JwtViewer jwt={jwt} contentType="application/trust-mark+jwt" />
				</CardContent>
			</Card>
		</div>
	);
}
