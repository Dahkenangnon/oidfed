import { type JWK, jwkThumbprint } from "@oidfed/core";
import { Badge, Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@oidfed/ui";
import { useEffect, useState } from "react";
import { CopyButton } from "./copy-button";

interface JwkTableProps {
	readonly jwks: { keys: readonly Record<string, unknown>[] };
}

function useJwkThumbprints(keys: readonly Record<string, unknown>[]): Map<number, string> {
	const [thumbprints, setThumbprints] = useState<Map<number, string>>(new Map());

	useEffect(() => {
		let cancelled = false;
		const compute = async () => {
			const results = new Map<number, string>();
			for (let i = 0; i < keys.length; i++) {
				try {
					const tp = await jwkThumbprint(keys[i] as JWK);
					results.set(i, tp);
				} catch {
					// skip keys that can't be thumbprinted
				}
			}
			if (!cancelled) setThumbprints(results);
		};
		compute();
		return () => {
			cancelled = true;
		};
	}, [keys]);

	return thumbprints;
}

export function JwkTable({ jwks }: JwkTableProps) {
	const thumbprints = useJwkThumbprints(jwks.keys ?? []);

	if (!jwks.keys || jwks.keys.length === 0) {
		return <p className="text-sm text-muted-foreground">No keys found.</p>;
	}

	return (
		<div className="rounded-lg border">
			<Table>
				<TableHeader>
					<TableRow>
						<TableHead>kid</TableHead>
						<TableHead>kty</TableHead>
						<TableHead>alg</TableHead>
						<TableHead>use</TableHead>
						<TableHead>crv</TableHead>
						<TableHead>Thumbprint (SHA-256)</TableHead>
					</TableRow>
				</TableHeader>
				<TableBody>
					{jwks.keys.map((key, i) => {
						const tp = thumbprints.get(i);
						return (
							<TableRow key={String(key.kid ?? i)}>
								<TableCell className="font-mono text-xs">{String(key.kid ?? "—")}</TableCell>
								<TableCell>
									<Badge variant="outline">{String(key.kty ?? "—")}</Badge>
								</TableCell>
								<TableCell className="font-mono text-xs">{String(key.alg ?? "—")}</TableCell>
								<TableCell>{String(key.use ?? "—")}</TableCell>
								<TableCell className="font-mono text-xs">{String(key.crv ?? "—")}</TableCell>
								<TableCell>
									{tp ? (
										<span className="inline-flex items-center gap-1">
											<span className="font-mono text-xs" title={tp}>
												{tp.slice(0, 16)}…
											</span>
											<CopyButton value={tp} className="size-6" />
										</span>
									) : (
										<span className="text-xs text-muted-foreground">—</span>
									)}
								</TableCell>
							</TableRow>
						);
					})}
				</TableBody>
			</Table>
		</div>
	);
}
