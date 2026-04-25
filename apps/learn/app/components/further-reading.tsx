import { ArrowUpRight, BookOpen, FileText, Globe } from "lucide-react";
import { RFCRef } from "./rfc-ref";
import { SpecRef } from "./spec-ref";

export interface SpecSectionRef {
	sec: string;
	title: string;
}

export interface RFCReference {
	num: number;
	title: string;
}

export interface ExternalRef {
	title: string;
	source: string;
	date?: string | undefined;
	href: string;
}

interface FurtherReadingProps {
	specSections?: SpecSectionRef[] | undefined;
	rfcs?: RFCReference[] | undefined;
	external?: ExternalRef[] | undefined;
}

/**
 * End-of-lesson "Further reading" block rendered before the prev/next navigation.
 * Groups references by provenance: normative spec sections, normative RFCs, and curated
 * external reading (adoption narratives, implementation guides). Mirrors the visual
 * language of `apps/home/app/routes/ecosystem.tsx:furtherReading`.
 */
export function FurtherReading({ specSections, rfcs, external }: FurtherReadingProps) {
	const hasAny =
		(specSections && specSections.length > 0) ||
		(rfcs && rfcs.length > 0) ||
		(external && external.length > 0);
	if (!hasAny) return null;

	return (
		<section
			aria-labelledby="further-reading-title"
			className="not-prose mt-14 border-t border-border/60 pt-10"
		>
			<div className="flex items-center gap-3 font-mono text-[11px] uppercase tracking-[0.18em] text-muted-foreground">
				<span className="inline-flex size-1.5 rounded-full bg-brand-500" aria-hidden />
				<span id="further-reading-title">Further reading</span>
				<span className="h-px w-8 bg-border" aria-hidden />
			</div>

			<div className="mt-6 grid gap-8 sm:grid-cols-2">
				{specSections && specSections.length > 0 && (
					<div>
						<RowHeader icon={<BookOpen className="size-3.5" />} label="Normative spec" />
						<ul className="mt-3 flex flex-wrap gap-2">
							{specSections.map((s) => (
								<li key={s.sec}>
									<SpecRef sec={s.sec} title={s.title} size="block" />
								</li>
							))}
						</ul>
					</div>
				)}

				{rfcs && rfcs.length > 0 && (
					<div>
						<RowHeader icon={<FileText className="size-3.5" />} label="Normative RFCs" />
						<ul className="mt-3 flex flex-wrap gap-2">
							{rfcs.map((r) => (
								<li key={r.num}>
									<RFCRef rfc={r.num} title={r.title} size="block" />
								</li>
							))}
						</ul>
					</div>
				)}
			</div>

			{external && external.length > 0 && (
				<div className="mt-8">
					<RowHeader icon={<Globe className="size-3.5" />} label="External reading" />
					<ul className="mt-3 divide-y divide-border/60 rounded-xl border border-border/60 bg-card/40">
						{external.map((e) => (
							<li key={e.href}>
								<a
									href={e.href}
									target="_blank"
									rel="noopener noreferrer"
									className="group grid grid-cols-[1fr_auto] items-start gap-4 p-4 no-underline transition-colors hover:bg-muted/50"
								>
									<div className="min-w-0">
										<div className="font-heading text-[14.5px] font-semibold leading-snug tracking-tight text-foreground">
											{e.title}
										</div>
										<div className="mt-1 font-mono text-[10.5px] uppercase tracking-[0.18em] text-muted-foreground">
											{e.source}
											{e.date && <> · {e.date}</>}
										</div>
									</div>
									<ArrowUpRight className="size-4 shrink-0 text-muted-foreground transition-colors group-hover:text-brand-500" />
								</a>
							</li>
						))}
					</ul>
				</div>
			)}
		</section>
	);
}

function RowHeader({ icon, label }: { icon: React.ReactNode; label: string }) {
	return (
		<div className="flex items-center gap-2 font-mono text-[10.5px] uppercase tracking-[0.18em] text-muted-foreground">
			<span>{icon}</span>
			<span>{label}</span>
			<span className="h-px flex-1 bg-border" aria-hidden />
		</div>
	);
}
