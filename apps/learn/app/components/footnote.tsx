import { Separator } from "@oidfed/ui";

export interface Source {
	id: string;
	text: string;
	url?: string;
}

export function Ref({ id }: { id: string }) {
	return (
		<sup>
			<a href={`#ref-${id}`} className="text-primary hover:underline text-xs">
				[{id}]
			</a>
		</sup>
	);
}

export function SourcesSection({ sources }: { sources: Source[] }) {
	if (sources.length === 0) return null;
	return (
		<section className="mt-12">
			<Separator className="mb-6" />
			<h3 className="text-lg font-semibold mb-4">Sources & References</h3>
			<ol className="list-decimal list-inside space-y-2 text-sm text-muted-foreground">
				{sources.map((s) => (
					<li key={s.id} id={`ref-${s.id}`}>
						{s.url ? (
							<a
								href={s.url}
								target="_blank"
								rel="noopener noreferrer"
								className="hover:text-foreground hover:underline"
							>
								{s.text}
							</a>
						) : (
							s.text
						)}
					</li>
				))}
			</ol>
		</section>
	);
}
