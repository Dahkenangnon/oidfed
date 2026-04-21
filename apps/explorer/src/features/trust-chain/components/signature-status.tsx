import { Badge } from "@oidfed/ui";
import { ValidationBadge } from "@/components/shared/validation-badge";

interface SignatureStatusProps {
	readonly kid?: string | undefined;
	readonly alg?: string | undefined;
	readonly valid: boolean;
}

export function SignatureStatus({ kid, alg, valid }: SignatureStatusProps) {
	return (
		<div className="flex items-center gap-2 flex-wrap">
			<ValidationBadge status={valid ? "pass" : "fail"} label={valid ? "Verified" : "Invalid"} />
			{alg && (
				<Badge variant="outline" className="font-mono text-xs">
					{alg}
				</Badge>
			)}
			{kid && (
				<Badge variant="outline" className="font-mono text-xs max-w-48 truncate">
					kid: {kid}
				</Badge>
			)}
		</div>
	);
}
