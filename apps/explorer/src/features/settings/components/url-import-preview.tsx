/**
 * URL-based settings import — preview & confirm component.
 *
 * Rendered inline at the top of the Settings page whenever the URL carries
 * a `?import=<url>` query parameter. Fetches the remote document, validates
 * it against `SettingsSchema`, and presents a non-destructive preview so
 * the visitor can choose between an additive merge (default) and a full
 * replace, or cancel without applying anything.
 */

import { Alert, AlertDescription, Button, Card, CardContent } from "@oidfed/ui";
import { AlertTriangle, CheckCircle2, Loader2, Shield, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import type { Settings } from "@/lib/settings";
import {
	diffAnchors,
	type FetchError,
	type FetchedSettings,
	fetchSettings,
	mergeSettings,
} from "../lib/url-import.js";

interface UrlImportPreviewProps {
	readonly importUrl: string;
	readonly currentSettings: Settings;
	readonly onApplyMerge: (next: Settings) => void;
	readonly onApplyReplace: (next: Settings) => void;
	readonly onDismiss: () => void;
}

type LoadState =
	| { readonly status: "loading" }
	| { readonly status: "preview"; readonly fetched: FetchedSettings }
	| { readonly status: "error"; readonly error: FetchError }
	| { readonly status: "applied"; readonly mode: "merge" | "replace"; readonly added: number };

export function UrlImportPreview({
	importUrl,
	currentSettings,
	onApplyMerge,
	onApplyReplace,
	onDismiss,
}: UrlImportPreviewProps) {
	const [state, setState] = useState<LoadState>({ status: "loading" });
	const [confirmReplace, setConfirmReplace] = useState(false);
	const ctrlRef = useRef<AbortController | null>(null);

	useEffect(() => {
		ctrlRef.current?.abort();
		const ctrl = new AbortController();
		ctrlRef.current = ctrl;
		setState({ status: "loading" });
		setConfirmReplace(false);

		fetchSettings(importUrl, { signal: ctrl.signal })
			.then((result) => {
				if (ctrl.signal.aborted) return;
				if (result.ok) {
					setState({ status: "preview", fetched: result.value });
				} else {
					setState({ status: "error", error: result.error });
				}
			})
			.catch((err: unknown) => {
				if (ctrl.signal.aborted) return;
				setState({
					status: "error",
					error: {
						kind: "network",
						message: err instanceof Error ? err.message : String(err),
					},
				});
			});

		return () => ctrl.abort();
	}, [importUrl]);

	return (
		<Card className="border-brand-500/30 bg-brand-500/5">
			<CardContent className="space-y-4 p-5">
				<div className="flex items-start gap-3">
					<Shield className="size-5 shrink-0 text-brand-500 mt-0.5" />
					<div className="min-w-0 flex-1">
						<div className="flex items-start justify-between gap-3">
							<div className="min-w-0">
								<h2 className="text-sm font-semibold tracking-tight">
									Quick setup — import settings from URL
								</h2>
								<p
									className="mt-0.5 truncate font-mono text-xs text-muted-foreground"
									title={importUrl}
								>
									{importUrl}
								</p>
							</div>
							<Button variant="ghost" size="icon" onClick={onDismiss} aria-label="Cancel import">
								<X className="size-4" />
							</Button>
						</div>

						<div className="mt-4">
							{state.status === "loading" ? (
								<LoadingRow />
							) : state.status === "error" ? (
								<ErrorRow error={state.error} />
							) : state.status === "preview" ? (
								<PreviewBody
									fetched={state.fetched}
									current={currentSettings}
									confirmReplace={confirmReplace}
									onMerge={() => {
										const next = mergeSettings(currentSettings, state.fetched.settings);
										const { toAdd } = diffAnchors(
											currentSettings.trustAnchors,
											state.fetched.settings.trustAnchors,
										);
										onApplyMerge(next);
										setState({ status: "applied", mode: "merge", added: toAdd.length });
									}}
									onAskReplace={() => setConfirmReplace(true)}
									onCancelReplace={() => setConfirmReplace(false)}
									onConfirmReplace={() => {
										onApplyReplace(state.fetched.settings);
										setState({
											status: "applied",
											mode: "replace",
											added: state.fetched.settings.trustAnchors.length,
										});
									}}
								/>
							) : (
								<AppliedRow mode={state.mode} added={state.added} onDismiss={onDismiss} />
							)}
						</div>
					</div>
				</div>
			</CardContent>
		</Card>
	);
}

function LoadingRow() {
	return (
		<div className="flex items-center gap-2 text-sm text-muted-foreground">
			<Loader2 className="size-4 animate-spin" />
			Fetching settings document…
		</div>
	);
}

function ErrorRow({ error }: { readonly error: FetchError }) {
	return (
		<Alert variant="error">
			<AlertTriangle className="size-4" />
			<AlertDescription className="space-y-1">
				<div className="font-medium">Could not import settings ({error.kind}).</div>
				<div className="text-xs text-muted-foreground">{error.message}</div>
			</AlertDescription>
		</Alert>
	);
}

function AppliedRow({
	mode,
	added,
	onDismiss,
}: {
	readonly mode: "merge" | "replace";
	readonly added: number;
	readonly onDismiss: () => void;
}) {
	return (
		<div className="flex items-center justify-between gap-3">
			<div className="flex items-center gap-2 text-sm">
				<CheckCircle2 className="size-4 text-emerald-500" />
				<span>
					{mode === "merge"
						? `${added} trust anchor${added === 1 ? "" : "s"} added.`
						: `Settings replaced (${added} trust anchor${added === 1 ? "" : "s"} now configured).`}
				</span>
			</div>
			<Button variant="ghost" size="sm" onClick={onDismiss}>
				Dismiss
			</Button>
		</div>
	);
}

function PreviewBody({
	fetched,
	current,
	confirmReplace,
	onMerge,
	onAskReplace,
	onCancelReplace,
	onConfirmReplace,
}: {
	readonly fetched: FetchedSettings;
	readonly current: Settings;
	readonly confirmReplace: boolean;
	readonly onMerge: () => void;
	readonly onAskReplace: () => void;
	readonly onCancelReplace: () => void;
	readonly onConfirmReplace: () => void;
}) {
	const { toAdd, alreadyPresent } = diffAnchors(
		current.trustAnchors,
		fetched.settings.trustAnchors,
	);
	const scalarDiff = computeScalarDiff(current, fetched.settings);
	const nothingNew = toAdd.length === 0 && scalarDiff.length === 0;

	return (
		<div className="space-y-4">
			<section className="space-y-2">
				<div className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
					Trust anchors ({fetched.settings.trustAnchors.length} in document)
				</div>
				{toAdd.length === 0 && alreadyPresent.length === 0 ? (
					<p className="text-xs italic text-muted-foreground">None.</p>
				) : (
					<ul className="space-y-1 text-xs font-mono">
						{toAdd.map((a) => (
							<li key={a.entityId} className="flex items-start gap-2">
								<span className="mt-0.5 inline-block rounded-sm bg-emerald-500/15 px-1 text-[10px] font-semibold tracking-wide text-emerald-700 dark:text-emerald-300">
									NEW
								</span>
								<span className="break-all">{a.entityId}</span>
							</li>
						))}
						{alreadyPresent.map((a) => (
							<li key={a.entityId} className="flex items-start gap-2 text-muted-foreground">
								<span className="mt-0.5 inline-block rounded-sm bg-muted px-1 text-[10px] font-semibold tracking-wide">
									SKIP
								</span>
								<span className="break-all line-through opacity-60">{a.entityId}</span>
							</li>
						))}
					</ul>
				)}
			</section>

			{scalarDiff.length > 0 ? (
				<section className="space-y-2">
					<div className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
						Other settings (replace only)
					</div>
					<ul className="space-y-1 text-xs">
						{scalarDiff.map((d) => (
							<li key={d.key} className="flex items-baseline gap-2 font-mono">
								<span className="text-muted-foreground">{d.key}:</span>
								<span className="line-through text-muted-foreground/70">
									{JSON.stringify(d.current)}
								</span>
								<span aria-hidden>→</span>
								<span>{JSON.stringify(d.incoming)}</span>
							</li>
						))}
					</ul>
				</section>
			) : null}

			{nothingNew ? (
				<p className="rounded-md border border-dashed p-3 text-xs text-muted-foreground">
					Nothing to add — every trust anchor in the imported document is already in your settings,
					and the scalar fields all match.
				</p>
			) : null}

			{confirmReplace ? (
				<Alert variant="warning">
					<AlertTriangle className="size-4" />
					<AlertDescription className="space-y-3">
						<div>
							<strong>Replace all settings?</strong> Your existing trust anchors will be removed and
							every scalar (theme, timeouts…) will be overwritten with the imported values. This
							cannot be undone.
						</div>
						<div className="flex gap-2">
							<Button variant="destructive" size="sm" onClick={onConfirmReplace}>
								Yes, replace everything
							</Button>
							<Button variant="ghost" size="sm" onClick={onCancelReplace}>
								Back
							</Button>
						</div>
					</AlertDescription>
				</Alert>
			) : (
				<div className="flex flex-wrap items-center gap-2">
					<Button
						onClick={onMerge}
						disabled={toAdd.length === 0}
						className="bg-brand-500 hover:bg-brand-600"
					>
						{toAdd.length === 0
							? "All anchors already present"
							: `Add ${toAdd.length} anchor${toAdd.length === 1 ? "" : "s"}`}
					</Button>
					<Button variant="outline" onClick={onAskReplace}>
						Replace all settings…
					</Button>
				</div>
			)}
		</div>
	);
}

interface ScalarDiffEntry {
	readonly key: string;
	readonly current: unknown;
	readonly incoming: unknown;
}

function computeScalarDiff(current: Settings, incoming: Settings): ReadonlyArray<ScalarDiffEntry> {
	const diffs: ScalarDiffEntry[] = [];
	const keys: ReadonlyArray<keyof Settings> = [
		"httpTimeoutMs",
		"maxChainDepth",
		"theme",
		"jsonIndent",
		"expirationWarningDays",
	];
	for (const key of keys) {
		const a = current[key];
		const b = incoming[key];
		if (JSON.stringify(a) !== JSON.stringify(b)) {
			diffs.push({ key, current: a, incoming: b });
		}
	}
	return diffs;
}
