import { ExternalLink } from "lucide-react";
import { useNavigate } from "react-router";

interface EntityLinkProps {
	readonly entityId: string;
	readonly className?: string;
}

export function EntityLink({ entityId, className }: EntityLinkProps) {
	const navigate = useNavigate();

	return (
		<button
			type="button"
			onClick={() => navigate(`/entity/${encodeURIComponent(entityId)}`)}
			className={`inline-flex items-center gap-1 font-mono text-sm text-brand-500 hover:text-brand-600 hover:underline ${className ?? ""}`}
		>
			{entityId}
			<ExternalLink className="size-3" />
		</button>
	);
}
