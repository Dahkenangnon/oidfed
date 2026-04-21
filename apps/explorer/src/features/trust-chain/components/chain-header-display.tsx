import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@oidfed/ui";
import { CodeBlock } from "@/components/shared/code-block";

interface ChainHeaderDisplayProps {
	readonly statements: readonly string[];
}

function tryDecodeBase64Url(s: string): Record<string, unknown> | null {
	try {
		const parsed: unknown = JSON.parse(atob(s.replace(/-/g, "+").replace(/_/g, "/")));
		if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) {
			return parsed as Record<string, unknown>;
		}
		return null;
	} catch {
		return null;
	}
}

function getJwtLabel(index: number, total: number): string {
	if (index === 0) return "Entity Configuration";
	if (index === total - 1) return "Trust Anchor";
	return `Subordinate Statement ${index}`;
}

export function ChainHeaderDisplay({ statements }: ChainHeaderDisplayProps) {
	return (
		<div className="space-y-4">
			<h3 className="text-sm font-medium text-muted-foreground">
				trust_chain JWS array ({statements.length} statements)
			</h3>
			<Accordion>
				{statements.map((jwt, i) => {
					const parts = jwt.split(".");
					const [headerPart, payloadPart, sigPart] = parts;
					const decodedHeader = headerPart ? tryDecodeBase64Url(headerPart) : null;
					const decodedPayload = payloadPart ? tryDecodeBase64Url(payloadPart) : null;

					return (
						<AccordionItem
							// biome-ignore lint/suspicious/noArrayIndexKey: statements ordered by chain position
							key={`jwt-${i}`}
							value={String(i)}
						>
							<AccordionTrigger className="text-xs font-mono">
								<span className="text-muted-foreground mr-2">[{i}]</span>
								<span className="font-medium">{getJwtLabel(i, statements.length)}</span>
							</AccordionTrigger>
							<AccordionContent>
								<div className="space-y-3">
									<div className="font-mono text-xs break-all leading-relaxed rounded-md border bg-muted/30 p-3">
										<span className="text-blue-500 dark:text-blue-400">{headerPart ?? ""}</span>
										<span className="text-muted-foreground">.</span>
										<span className="text-emerald-600 dark:text-emerald-400">
											{payloadPart ?? ""}
										</span>
										<span className="text-muted-foreground">.</span>
										<span className="text-orange-500 dark:text-orange-400">{sigPart ?? ""}</span>
									</div>
									{decodedHeader && (
										<div>
											<p className="text-xs font-medium text-blue-500 dark:text-blue-400 mb-1">
												Header
											</p>
											<CodeBlock code={JSON.stringify(decodedHeader, null, 2)} />
										</div>
									)}
									{decodedPayload && (
										<div>
											<p className="text-xs font-medium text-emerald-600 dark:text-emerald-400 mb-1">
												Payload
											</p>
											<CodeBlock code={JSON.stringify(decodedPayload, null, 2)} />
										</div>
									)}
								</div>
							</AccordionContent>
						</AccordionItem>
					);
				})}
			</Accordion>
		</div>
	);
}
