import { Badge, Button, Skeleton } from "@oidfed/ui";
import { useEffect, useState } from "react";
import { CopyButton } from "@/components/shared/copy-button";
import { EntityLink } from "@/components/shared/entity-link";
import type { EnrichedEntity } from "../hooks/use-subordinate-enrichment";

const PAGE_SIZE = 20;

interface SubordinateListProps {
	readonly entityIds: readonly string[];
	readonly enrichment?: ReadonlyMap<string, EnrichedEntity> | undefined;
	readonly enrichmentLoading?: boolean | undefined;
}

export function SubordinateList({
	entityIds,
	enrichment,
	enrichmentLoading,
}: SubordinateListProps) {
	const [page, setPage] = useState(0);

	// Reset page when entityIds changes
	// biome-ignore lint/correctness/useExhaustiveDependencies: entityIds identity change means new data
	useEffect(() => {
		setPage(0);
	}, [entityIds]);

	const totalPages = Math.ceil(entityIds.length / PAGE_SIZE);
	const pageIds = entityIds.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

	if (entityIds.length === 0) return null;

	return (
		<div className="space-y-3">
			<div className="flex items-center justify-between">
				<div className="flex items-center gap-2">
					<h3 className="text-sm font-medium">Subordinates</h3>
					<Badge variant="secondary">{entityIds.length}</Badge>
				</div>
				{totalPages > 1 && (
					<div className="flex items-center gap-2 text-sm text-muted-foreground">
						Page {page + 1} of {totalPages}
					</div>
				)}
			</div>

			<div className="rounded-lg border divide-y">
				{pageIds.map((id) => {
					const info = enrichment?.get(id);
					const isLoading = enrichmentLoading && !info;

					return (
						<div
							key={id}
							className="flex items-center justify-between gap-3 px-4 py-2.5 hover:bg-muted/30"
						>
							<div className="flex flex-col gap-0.5 min-w-0 flex-1">
								<div className="flex items-center gap-2">
									<EntityLink entityId={id} />
									{info?.organizationName && (
										<span className="text-xs text-muted-foreground truncate">
											{info.organizationName}
										</span>
									)}
									{isLoading && <Skeleton className="h-3.5 w-24" />}
								</div>
								{info && (
									<div className="flex items-center gap-1.5">
										{info.entityTypes.map((type) => (
											<Badge key={type} variant="outline" className="text-[10px] px-1.5 py-0">
												{type}
											</Badge>
										))}
										{info.trustMarkCount > 0 && (
											<Badge variant="secondary" className="text-[10px] px-1.5 py-0">
												{info.trustMarkCount} TM
											</Badge>
										)}
									</div>
								)}
							</div>
							<CopyButton value={id} />
						</div>
					);
				})}
			</div>

			{totalPages > 1 && (
				<div className="flex items-center justify-center gap-2">
					<Button
						variant="outline"
						size="sm"
						disabled={page === 0}
						onClick={() => setPage((p) => p - 1)}
					>
						Previous
					</Button>
					<span className="text-sm text-muted-foreground">
						{page + 1} / {totalPages}
					</span>
					<Button
						variant="outline"
						size="sm"
						disabled={page >= totalPages - 1}
						onClick={() => setPage((p) => p + 1)}
					>
						Next
					</Button>
				</div>
			)}
		</div>
	);
}
