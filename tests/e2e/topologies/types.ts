export interface TopologyDefinition {
	name: string;
	description: string;
	entities: EntityDefinition[];
}

export interface EntityDefinition {
	id: string;
	role: "trust-anchor" | "intermediate" | "leaf";
	protocolRole?: "op" | "rp";
	authorityHints?: string[];
	metadata: Record<string, Record<string, unknown>>;
	metadataPolicy?: Record<string, Record<string, unknown>>;
	constraints?: { max_path_length?: number };
	trustMarkIssuers?: Record<string, string[]>;
	trustMarks?: Array<{ trust_mark_type: string; jwt: string }>;
	trustMarkOwners?: Record<string, { sub: string; jwks: { keys: unknown[] } }>;
	trustMarkDelegations?: Record<string, string>;
	entityConfigurationTtlSeconds?: number;
}
