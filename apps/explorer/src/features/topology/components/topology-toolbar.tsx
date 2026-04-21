import {
	Badge,
	Button,
	Input,
	Select,
	SelectContent,
	SelectItem,
	SelectTrigger,
	SelectValue,
} from "@oidfed/ui";
import {
	BarChart3,
	ChevronDown,
	ChevronLeft,
	ChevronRight,
	Download,
	Filter,
	LayoutGrid,
	Search,
	TreePine,
	X,
} from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { downloadText, exportDot, exportMermaid } from "@/lib/topology-export";
import type { UseTopologyGraphResult } from "../hooks/use-topology-graph";
import type { LayoutDirection, SubordinateFilters } from "../types";

interface TopologyToolbarProps {
	readonly graph: UseTopologyGraphResult;
	readonly layoutDir: LayoutDirection;
	readonly onLayoutChange: (dir: LayoutDirection) => void;
	readonly filters: SubordinateFilters;
	readonly onFiltersChange: (f: SubordinateFilters) => void;
	readonly metricsOpen: boolean;
	readonly onMetricsToggle: () => void;
	readonly onExportPng: () => void;
	readonly onExportSvg: () => void;
}

function countActiveFilters(filters: SubordinateFilters): number {
	let count = 0;
	if (filters.entity_type) count++;
	if (filters.intermediate) count++;
	if (filters.trust_marked) count++;
	return count;
}

export function TopologyToolbar({
	graph,
	layoutDir,
	onLayoutChange,
	filters,
	onFiltersChange,
	metricsOpen,
	onMetricsToggle,
	onExportPng,
	onExportSvg,
}: TopologyToolbarProps) {
	const [searchInput, setSearchInput] = useState("");
	const [filtersOpen, setFiltersOpen] = useState(false);
	const [exportOpen, setExportOpen] = useState(false);
	const filtersRef = useRef<HTMLDivElement>(null);
	const exportRef = useRef<HTMLDivElement>(null);
	const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

	useEffect(() => {
		if (debounceRef.current) clearTimeout(debounceRef.current);
		debounceRef.current = setTimeout(() => {
			graph.setSearchQuery(searchInput);
		}, 300);
		return () => {
			if (debounceRef.current) clearTimeout(debounceRef.current);
		};
	}, [searchInput, graph.setSearchQuery]);

	// Click-outside handler for filters and export dropdowns
	useEffect(() => {
		function handleClickOutside(e: MouseEvent) {
			if (filtersOpen && filtersRef.current && !filtersRef.current.contains(e.target as Node)) {
				setFiltersOpen(false);
			}
			if (exportOpen && exportRef.current && !exportRef.current.contains(e.target as Node)) {
				setExportOpen(false);
			}
		}
		document.addEventListener("mousedown", handleClickOutside);
		return () => document.removeEventListener("mousedown", handleClickOutside);
	}, [filtersOpen, exportOpen]);

	const handleExportMermaid = useCallback(() => {
		const content = exportMermaid(graph.nodes, graph.edges);
		downloadText(content, "federation-topology.mmd", "text/plain");
		setExportOpen(false);
	}, [graph.nodes, graph.edges]);

	const handleExportDot = useCallback(() => {
		const content = exportDot(graph.nodes, graph.edges);
		downloadText(content, "federation-topology.dot", "text/plain");
		setExportOpen(false);
	}, [graph.nodes, graph.edges]);

	const handleClearFilters = useCallback(() => {
		onFiltersChange({});
	}, [onFiltersChange]);

	const { entityCount, maxDepth, branchingFactor, intermediateRatio } = graph.metrics;
	const activeFilterCount = countActiveFilters(filters);

	return (
		<div className="space-y-2">
			<div className="flex flex-wrap items-center gap-2">
				{/* Layout toggle */}
				<div className="flex items-center border rounded-md overflow-hidden divide-x">
					<button
						type="button"
						onClick={() => onLayoutChange("fcose")}
						className={`px-2.5 py-1.5 text-xs flex items-center gap-1.5 transition-colors ${
							layoutDir === "fcose" ? "bg-primary text-primary-foreground" : "hover:bg-muted"
						}`}
					>
						<LayoutGrid className="size-3" />
						Force
					</button>
					<button
						type="button"
						onClick={() => onLayoutChange("breadthfirst")}
						className={`px-2.5 py-1.5 text-xs flex items-center gap-1.5 transition-colors ${
							layoutDir === "breadthfirst" ? "bg-primary text-primary-foreground" : "hover:bg-muted"
						}`}
					>
						<TreePine className="size-3" />
						Tree
					</button>
				</div>

				{/* Search with navigation */}
				<div className="flex items-center gap-1">
					<div className="relative">
						<Search className="absolute left-2 top-1/2 -translate-y-1/2 size-3.5 text-muted-foreground" />
						<Input
							placeholder="Search entities (regex)…"
							value={searchInput}
							onChange={(e) => setSearchInput(e.target.value)}
							className="pl-7 h-8 w-48 text-xs"
						/>
					</div>
					{graph.matchedNodeIds.length > 0 && (
						<>
							<Badge variant="secondary" className="text-xs font-normal tabular-nums">
								{graph.focusedMatchIndex + 1}/{graph.matchedNodeIds.length}
							</Badge>
							<Button
								variant="ghost"
								size="icon"
								className="size-7"
								onClick={() => graph.focusMatch(graph.focusedMatchIndex - 1)}
							>
								<ChevronLeft className="size-3.5" />
							</Button>
							<Button
								variant="ghost"
								size="icon"
								className="size-7"
								onClick={() => graph.focusMatch(graph.focusedMatchIndex + 1)}
							>
								<ChevronRight className="size-3.5" />
							</Button>
						</>
					)}
				</div>

				{/* Filters — click-toggle with click-outside-to-close */}
				<div className="relative" ref={filtersRef}>
					<Button
						variant={activeFilterCount > 0 ? "default" : "outline"}
						size="sm"
						className="h-8 text-xs"
						onClick={() => setFiltersOpen((o) => !o)}
					>
						<Filter className="size-3.5 mr-1.5" />
						Filters
						{activeFilterCount > 0 && (
							<Badge
								variant="secondary"
								className="ml-1.5 size-4 p-0 flex items-center justify-center text-[10px] rounded-full"
							>
								{activeFilterCount}
							</Badge>
						)}
						<ChevronDown
							className={`size-3 ml-1 transition-transform ${filtersOpen ? "rotate-180" : ""}`}
						/>
					</Button>
					{filtersOpen && (
						<div className="absolute z-20 mt-1 rounded-lg border bg-popover shadow-md p-3 space-y-3 w-60">
							<div className="flex items-center justify-between">
								<p className="text-xs font-medium">Subordinate Filters</p>
								{activeFilterCount > 0 && (
									<button
										type="button"
										onClick={handleClearFilters}
										className="text-[10px] text-muted-foreground hover:text-foreground flex items-center gap-0.5"
									>
										<X className="size-3" />
										Clear all
									</button>
								)}
							</div>
							<p className="text-[10px] text-muted-foreground -mt-1">
								Applied automatically to new expansions
							</p>
							<div className="space-y-1">
								<p className="text-xs font-medium">Entity Type</p>
								<Select
									value={filters.entity_type ?? ""}
									onValueChange={(v) =>
										onFiltersChange({ ...filters, entity_type: v || undefined })
									}
								>
									<SelectTrigger className="h-7 text-xs">
										<SelectValue placeholder="Any" />
									</SelectTrigger>
									<SelectContent>
										<SelectItem value="">Any</SelectItem>
										<SelectItem value="openid_provider">OpenID Provider</SelectItem>
										<SelectItem value="openid_relying_party">Relying Party</SelectItem>
										<SelectItem value="oauth_authorization_server">Auth Server</SelectItem>
										<SelectItem value="federation_entity">Federation Entity</SelectItem>
									</SelectContent>
								</Select>
							</div>
							<div className="flex items-center gap-2">
								<input
									id="filter-intermediate"
									type="checkbox"
									checked={filters.intermediate ?? false}
									onChange={(e) =>
										onFiltersChange({
											...filters,
											intermediate: e.target.checked ? true : undefined,
										})
									}
									className="size-3.5"
								/>
								<label htmlFor="filter-intermediate" className="text-xs">
									Intermediates only
								</label>
							</div>
							<div className="flex items-center gap-2">
								<input
									id="filter-trust-marked"
									type="checkbox"
									checked={filters.trust_marked ?? false}
									onChange={(e) =>
										onFiltersChange({
											...filters,
											trust_marked: e.target.checked ? true : undefined,
										})
									}
									className="size-3.5"
								/>
								<label htmlFor="filter-trust-marked" className="text-xs">
									Trust-marked only
								</label>
							</div>
						</div>
					)}
				</div>

				{/* Metrics toggle */}
				<Button
					variant={metricsOpen ? "default" : "outline"}
					size="sm"
					className="h-8 text-xs"
					onClick={onMetricsToggle}
				>
					<BarChart3 className="size-3.5 mr-1.5" />
					Metrics
				</Button>

				<div className="flex-1" />

				{/* Inline metrics badges */}
				<div className="flex items-center gap-1.5 text-xs text-muted-foreground">
					<Badge variant="secondary" className="text-xs font-normal">
						{entityCount} entities
					</Badge>
					<Badge variant="secondary" className="text-xs font-normal">
						depth {maxDepth}
					</Badge>
					{branchingFactor > 0 && (
						<Badge variant="secondary" className="text-xs font-normal">
							avg {branchingFactor} subs
						</Badge>
					)}
					{intermediateRatio > 0 && (
						<Badge variant="secondary" className="text-xs font-normal">
							{intermediateRatio}% int.
						</Badge>
					)}
				</div>

				{/* Export — click-toggle dropdown */}
				<div className="relative" ref={exportRef}>
					<Button
						variant="outline"
						size="sm"
						className="h-8 text-xs"
						onClick={() => setExportOpen((o) => !o)}
					>
						<Download className="size-3.5 mr-1.5" />
						Export
						<ChevronDown
							className={`size-3 ml-1 transition-transform ${exportOpen ? "rotate-180" : ""}`}
						/>
					</Button>
					{exportOpen && (
						<div className="absolute right-0 top-full mt-1 z-20 rounded-lg border bg-popover shadow-md py-1 w-36">
							<button
								type="button"
								onClick={() => {
									onExportSvg();
									setExportOpen(false);
								}}
								className="w-full px-3 py-1.5 text-xs text-left hover:bg-accent"
							>
								SVG
							</button>
							<button
								type="button"
								onClick={() => {
									onExportPng();
									setExportOpen(false);
								}}
								className="w-full px-3 py-1.5 text-xs text-left hover:bg-accent"
							>
								PNG
							</button>
							<button
								type="button"
								onClick={handleExportMermaid}
								className="w-full px-3 py-1.5 text-xs text-left hover:bg-accent"
							>
								Mermaid
							</button>
							<button
								type="button"
								onClick={handleExportDot}
								className="w-full px-3 py-1.5 text-xs text-left hover:bg-accent"
							>
								DOT (Graphviz)
							</button>
						</div>
					)}
				</div>
			</div>
		</div>
	);
}
