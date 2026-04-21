import {
	applyMetadataPolicy,
	operators,
	type ParsedEntityStatement,
	resolveMetadataPolicy,
} from "@oidfed/core";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@oidfed/ui";
import { AlertTriangle, FlaskConical } from "lucide-react";
import { useMemo, useState } from "react";
import { JsonTree } from "@/components/shared/json-tree";
import { usePageTitle } from "@/hooks/use-page-title";
import { ResolvedMetadataDiff } from "../trust-chain/components/resolved-metadata-diff";
import { CombinationWarnings } from "./components/combination-warnings";
import { PolicyInputForm } from "./components/policy-input-form";
import { PolicyTree } from "./components/policy-tree";
import { usePolicyValidation } from "./hooks/use-policy-validation";

interface PolicyInputs {
	metadata: Record<string, unknown>;
	policyLevels: Record<string, unknown>[];
	metadataPolicyCrit?: string[] | undefined;
}

const STANDARD_OPERATORS = new Set<string>(Object.keys(operators));

export function PolicySimulatorPage() {
	usePageTitle("Policy Simulator — OidFed Explorer");
	const [inputs, setInputs] = useState<PolicyInputs | null>(null);

	const mergeResult = inputs
		? resolveMetadataPolicy(
				inputs.policyLevels.map(
					(policy, i) =>
						({
							payload: {
								iss: `simulator-level-${i}`,
								sub: `simulator-level-${i + 1}`,
								iat: 0,
								exp: 9_999_999_999,
								metadata_policy: policy,
								...(inputs.metadataPolicyCrit && i === 0
									? { metadata_policy_crit: inputs.metadataPolicyCrit }
									: {}),
							},
						}) as unknown as ParsedEntityStatement,
				),
			)
		: null;

	const originalMetadata = inputs?.metadata ?? null;
	const applyResult =
		mergeResult?.ok === true && originalMetadata
			? applyMetadataPolicy(originalMetadata, mergeResult.value)
			: null;

	const mergeError = mergeResult?.ok === false ? mergeResult.error : null;
	const applyError = applyResult?.ok === false ? applyResult.error : null;

	// Parse merge error for field-level highlighting
	const mergeErrorField = useMemo(() => {
		if (!mergeError) return null;
		// Try to extract field name from error description like "... field 'redirect_uris' ..."
		const match = mergeError.description.match(/field\s+'([^']+)'/);
		return match?.[1] ?? null;
	}, [mergeError]);

	// Operator combination validation
	const { warnings, conflictFields } = usePolicyValidation(inputs?.policyLevels ?? null);

	// Combine conflict fields from validation + merge error
	const allConflictFields = useMemo(() => {
		const combined = new Set(conflictFields);
		if (mergeErrorField && inputs) {
			// Try to find which entity type the field belongs to
			for (const level of inputs.policyLevels) {
				for (const entityType of Object.keys(level)) {
					const fields = level[entityType] as Record<string, unknown> | undefined;
					if (fields && mergeErrorField in fields) {
						combined.add(`${entityType}.${mergeErrorField}`);
					}
				}
			}
		}
		return combined;
	}, [conflictFields, mergeErrorField, inputs]);

	// Check metadata_policy_crit for unrecognized operators
	const critWarnings = useMemo(() => {
		if (!inputs?.metadataPolicyCrit) return [];
		return inputs.metadataPolicyCrit
			.filter((op) => !STANDARD_OPERATORS.has(op))
			.map((op) => `Unrecognized critical operator: '${op}'`);
	}, [inputs?.metadataPolicyCrit]);

	return (
		<div className="container max-w-4xl py-8 space-y-8">
			<header className="space-y-1">
				<div className="h-1 w-8 rounded-full bg-brand-500" />
				<h1 className="text-2xl font-bold">Policy Simulator</h1>
				<p className="text-muted-foreground">
					Apply metadata policies to entity metadata without a live federation.
				</p>
			</header>

			<PolicyInputForm onChange={setInputs} />

			{warnings.length > 0 && <CombinationWarnings warnings={warnings} />}

			{critWarnings.length > 0 && (
				<div className="rounded-lg border border-warning/50 bg-warning/10 px-4 py-3 space-y-1">
					<div className="flex items-center gap-2">
						<AlertTriangle className="size-4 text-warning-foreground shrink-0" />
						<span className="text-sm font-medium text-warning-foreground">
							metadata_policy_crit
						</span>
					</div>
					{critWarnings.map((msg) => (
						<p key={msg} className="text-xs text-warning-foreground pl-6">
							{msg}
						</p>
					))}
				</div>
			)}

			{!inputs && (
				<div className="flex flex-col items-center justify-center rounded-lg border border-dashed py-16">
					<div className="text-center space-y-2 text-muted-foreground">
						<FlaskConical className="size-10 mx-auto opacity-40 dark:opacity-30" />
						<p className="text-sm">
							Configure metadata and policy levels above to simulate policy application
						</p>
					</div>
				</div>
			)}

			{(mergeError || applyError) && (
				<div className="rounded-lg border border-destructive/50 bg-destructive/10 px-4 py-3 text-sm text-destructive">
					{mergeError
						? `Policy merge error: ${mergeError.description}`
						: `Policy apply error: ${applyError?.description}`}
				</div>
			)}

			{mergeResult?.ok === true && applyResult?.ok === true && (
				<Tabs defaultValue="merged">
					<TabsList>
						<TabsTrigger value="merged">Merged Policy</TabsTrigger>
						<TabsTrigger value="resolved">Resolved Metadata</TabsTrigger>
						<TabsTrigger value="diff">Diff</TabsTrigger>
					</TabsList>

					<TabsContent value="merged" className="mt-4">
						<PolicyTree
							policy={mergeResult.value as Record<string, Record<string, Record<string, unknown>>>}
							conflictFields={allConflictFields}
						/>
					</TabsContent>

					<TabsContent value="resolved" className="mt-4">
						<JsonTree data={applyResult.value} />
					</TabsContent>

					<TabsContent value="diff" className="mt-4">
						<ResolvedMetadataDiff
							originalMetadata={originalMetadata ?? {}}
							resolvedMetadata={applyResult.value as Record<string, Record<string, unknown>>}
						/>
					</TabsContent>
				</Tabs>
			)}
		</div>
	);
}
