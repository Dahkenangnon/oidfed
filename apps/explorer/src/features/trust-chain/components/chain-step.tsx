import type { ParsedEntityStatement } from "@oidfed/core";
import { Badge } from "@oidfed/ui";
import { ChevronDown, ChevronRight } from "lucide-react";
import { useState } from "react";
import { EntityLink } from "@/components/shared/entity-link";
import { JsonTree } from "@/components/shared/json-tree";
import { SignatureStatus } from "./signature-status";

interface ChainStepProps {
	readonly statement: ParsedEntityStatement;
	readonly index: number;
	readonly total: number;
	readonly signatureValid: boolean;
}

function getStepLabel(index: number, total: number): string {
	if (index === 0) return "Entity Configuration";
	if (index === total - 1) return "Trust Anchor";
	return `Subordinate Statement ${index}`;
}

export function ChainStep({ statement, index, total, signatureValid }: ChainStepProps) {
	const [expanded, setExpanded] = useState(false);
	const { header, payload } = statement;
	const iss = String(payload.iss ?? "");
	const sub = String(payload.sub ?? "");

	return (
		<div className="rounded-lg border bg-card">
			<button
				type="button"
				onClick={() => setExpanded(!expanded)}
				className="flex w-full items-center gap-3 p-3 text-left hover:bg-accent/50 transition-colors"
			>
				{expanded ? (
					<ChevronDown className="size-4 shrink-0" />
				) : (
					<ChevronRight className="size-4 shrink-0" />
				)}
				<div className="flex-1 min-w-0 space-y-1">
					<div className="flex items-center gap-2 flex-wrap">
						<Badge variant="secondary" className="text-xs">
							{getStepLabel(index, total)}
						</Badge>
						<SignatureStatus
							kid={header.kid as string | undefined}
							alg={header.alg as string | undefined}
							valid={signatureValid}
						/>
					</div>
					<div className="text-xs text-muted-foreground font-mono truncate">
						{iss === sub ? sub : `${iss} → ${sub}`}
					</div>
				</div>
				<Badge variant="outline" className="text-xs shrink-0">
					exp: {new Date(payload.exp * 1000).toISOString().slice(0, 10)}
				</Badge>
			</button>

			{expanded && (
				<div className="border-t p-3 space-y-3">
					<div className="flex gap-4 text-sm">
						<div>
							<span className="text-muted-foreground">Issuer: </span>
							<EntityLink entityId={iss} />
						</div>
						{iss !== sub && (
							<div>
								<span className="text-muted-foreground">Subject: </span>
								<EntityLink entityId={sub} />
							</div>
						)}
					</div>
					<div>
						<h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-2">
							Header
						</h4>
						<JsonTree data={header} collapsed={1} />
					</div>
					<div>
						<h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-2">
							Payload
						</h4>
						<JsonTree data={payload} collapsed={2} />
					</div>
				</div>
			)}
		</div>
	);
}
