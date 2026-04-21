export interface NavItem {
	readonly label: string;
	readonly path: string;
	readonly icon: string;
	readonly disabled: boolean;
}

export interface TrustAnchorConfig {
	readonly entityId: string;
	readonly jwks?: unknown;
}

export type Theme = "light" | "dark" | "system";

export type OutputFormat = "json" | "table";

export interface RecentEntity {
	readonly entityId: string;
	readonly timestamp: number;
}
