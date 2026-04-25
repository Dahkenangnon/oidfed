import { Alert, AlertDescription, AlertTitle, cn } from "@oidfed/ui";
import {
	AlertTriangle,
	BookMarked,
	Eye,
	Info,
	Lightbulb,
	OctagonAlert,
	Quote,
	ShieldAlert,
	Wrench,
} from "lucide-react";
import type { ReactNode } from "react";
import { SpecRef } from "./spec-ref";

export type CalloutVariant =
	| "note"
	| "tip"
	| "analogy"
	| "spec-quote"
	| "implementation-note"
	| "pitfall"
	| "security"
	| "privacy"
	| "must-not";

interface CalloutProps {
	variant: CalloutVariant;
	/** Optional callout title. If omitted, a sensible default is used per variant. */
	title?: string | undefined;
	/**
	 * For `spec-quote` / `security` / `privacy` / `must-not` / `implementation-note` variants:
	 * a spec §-section anchor rendered as a SpecRef chip in the callout footer.
	 */
	sec?: string | undefined;
	/** Optional human-readable title for the cited spec section (shown in SpecRef tooltip). */
	secTitle?: string | undefined;
	/** Optional micro-label override (e.g., "Operational guidance, not spec"). */
	label?: string | undefined;
	children: ReactNode;
	className?: string | undefined;
}

interface VariantConfig {
	alertVariant: "default" | "error" | "info" | "success" | "warning";
	icon: React.ComponentType<{ className?: string }>;
	defaultTitle: string;
	accentClass: string;
	defaultLabel?: string;
}

const VARIANTS: Record<CalloutVariant, VariantConfig> = {
	note: {
		alertVariant: "default",
		icon: Info,
		defaultTitle: "Note",
		accentClass: "",
	},
	tip: {
		alertVariant: "info",
		icon: Lightbulb,
		defaultTitle: "Tip",
		accentClass: "",
	},
	analogy: {
		alertVariant: "info",
		icon: Lightbulb,
		defaultTitle: "Real-world analogy",
		accentClass: "",
	},
	"spec-quote": {
		alertVariant: "default",
		icon: Quote,
		defaultTitle: "From the spec",
		accentClass: "border-brand-500/40 bg-brand-500/5 [&>svg]:text-brand-500",
	},
	"implementation-note": {
		alertVariant: "warning",
		icon: Wrench,
		defaultTitle: "Implementation note",
		accentClass: "",
		defaultLabel: "Operational guidance — not normative",
	},
	pitfall: {
		alertVariant: "error",
		icon: OctagonAlert,
		defaultTitle: "Pitfall",
		accentClass: "",
	},
	security: {
		alertVariant: "error",
		icon: ShieldAlert,
		defaultTitle: "Security",
		accentClass: "",
		defaultLabel: "Security consideration",
	},
	privacy: {
		alertVariant: "success",
		icon: Eye,
		defaultTitle: "Privacy",
		accentClass: "border-teal-500/40 bg-teal-500/5 [&>svg]:text-teal-500",
		defaultLabel: "Privacy consideration",
	},
	"must-not": {
		alertVariant: "error",
		icon: AlertTriangle,
		defaultTitle: "MUST NOT",
		accentClass: "border-destructive/50",
		defaultLabel: "Normative prohibition",
	},
};

/**
 * Pedagogical callout used throughout lessons. Variants distinguish normative spec
 * text from operational guidance, illustrative notes, security hazards, privacy
 * considerations, and explicit MUST-NOT prohibitions — so learners can weight each
 * claim appropriately.
 */
export function Callout({
	variant,
	title,
	sec,
	secTitle,
	label,
	children,
	className,
}: CalloutProps) {
	const config = VARIANTS[variant];
	const Icon = config.icon;
	const effectiveTitle = title ?? config.defaultTitle;
	const effectiveLabel = label ?? config.defaultLabel;
	const isSpecQuote = variant === "spec-quote";

	return (
		<Alert
			variant={config.alertVariant}
			className={cn("my-6 not-prose", config.accentClass, className)}
		>
			<Icon className="size-4" />
			<AlertTitle className="flex items-center gap-2">
				<span>{effectiveTitle}</span>
				{effectiveLabel && !title && (
					<span className="rounded-sm border border-current/30 px-1.5 py-0 font-mono text-[9.5px] font-normal uppercase tracking-[0.18em] opacity-70">
						{effectiveLabel}
					</span>
				)}
			</AlertTitle>
			<AlertDescription>
				<div className={isSpecQuote ? "italic leading-relaxed" : ""}>{children}</div>
				{sec && (
					<div className="mt-2">
						<SpecRef sec={sec} title={secTitle} />
					</div>
				)}
			</AlertDescription>
		</Alert>
	);
}

/** Shortcut for <Callout variant="must-not"> — emphasizes a normative prohibition. */
export function MustNot({
	sec,
	secTitle,
	children,
}: {
	sec?: string | undefined;
	secTitle?: string | undefined;
	children: ReactNode;
}) {
	return (
		<Callout variant="must-not" sec={sec} secTitle={secTitle}>
			{children}
		</Callout>
	);
}

/** Shortcut for <Callout variant="spec-quote"> — renders an italic verbatim-feel quote. */
export function SpecQuote({
	sec,
	secTitle,
	children,
}: {
	sec?: string | undefined;
	secTitle?: string | undefined;
	children: ReactNode;
}) {
	return (
		<Callout variant="spec-quote" sec={sec} secTitle={secTitle}>
			{children}
		</Callout>
	);
}

// Also export the icon map for convenient ad-hoc access if a lesson needs it.
export { BookMarked as CalloutRefIcon };
