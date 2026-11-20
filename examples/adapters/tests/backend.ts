import { Pool } from "pg";
import { postgresStorage, provisionPostgresStorage } from "../postgres.js";

export const postgresUrl = process.env.OIDFED_STORAGE_POSTGRES;
type Options = Omit<Parameters<typeof postgresStorage>[0], "pool" | "namespace">;

export async function openTestStorage(
	url: string,
	namespace: string,
	options?: Options,
	provision = true,
) {
	const pool = new Pool({ connectionString: url, connectionTimeoutMillis: 5000 });
	try {
		if (provision) await provisionPostgresStorage(pool);
		const storage = postgresStorage({ ...options, pool, namespace });
		return {
			storage,
			async seedRaw(kind: string, id: string, value: unknown) {
				await pool.query(
					`INSERT INTO oidfed.oidfed_storage_record (namespace, kind, id, payload, entity_order, namespace_key, id_key)
					 VALUES ($1, $2, $3, $4, $5, sha256(convert_to($1, 'UTF8')), sha256(convert_to($3, 'UTF8')))`,
					[
						namespace,
						kind,
						id,
						JSON.stringify(value),
						kind === "subordinate" ? Buffer.from(id, "utf16le").swap16() : null,
					],
				);
			},
			[Symbol.asyncDispose]: () => pool.end(),
		};
	} catch (error) {
		await pool.end();
		throw error;
	}
}
