import { operators, type PolicyOperatorDefinition } from "@oidfed/core";
import { useMemo } from "react";

export interface PolicyWarning {
	readonly entityType: string;
	readonly field: string;
	readonly op1: string;
	readonly op2: string;
	readonly message: string;
}

export function usePolicyValidation(policyLevels: Record<string, unknown>[] | null): {
	readonly warnings: PolicyWarning[];
	readonly conflictFields: ReadonlySet<string>;
} {
	return useMemo(() => {
		if (!policyLevels || policyLevels.length === 0) {
			return { warnings: [], conflictFields: new Set<string>() };
		}

		const warnings: PolicyWarning[] = [];
		const conflictFields = new Set<string>();

		// Collect all operators per entity type → field across levels
		const fieldOps = new Map<string, Map<string, { values: unknown[]; levels: number[] }>>();

		for (let level = 0; level < policyLevels.length; level++) {
			const policy = policyLevels[level];
			if (!policy || typeof policy !== "object") continue;

			for (const [entityType, fields] of Object.entries(policy)) {
				if (!fields || typeof fields !== "object") continue;

				for (const [fieldName, opsRaw] of Object.entries(fields as Record<string, unknown>)) {
					if (!opsRaw || typeof opsRaw !== "object") continue;
					const fieldKey = `${entityType}.${fieldName}`;

					let opMap = fieldOps.get(fieldKey);
					if (!opMap) {
						opMap = new Map();
						fieldOps.set(fieldKey, opMap);
					}

					for (const [opName, opValue] of Object.entries(opsRaw as Record<string, unknown>)) {
						let entry = opMap.get(opName);
						if (!entry) {
							entry = { values: [], levels: [] };
							opMap.set(opName, entry);
						}
						entry.values.push(opValue);
						entry.levels.push(level);
					}
				}
			}
		}

		// Check combination rules per field
		for (const [fieldKey, opMap] of fieldOps) {
			const [entityType, field] = fieldKey.split(".", 2) as [string, string];
			const opNames = [...opMap.keys()];

			for (let i = 0; i < opNames.length; i++) {
				for (let j = i + 1; j < opNames.length; j++) {
					const op1Name = opNames[i];
					const op2Name = opNames[j];
					if (!op1Name || !op2Name) continue;
					// Same operators merge via merge(), not canCombineWith
					if (op1Name === op2Name) continue;
					const op1Def = operators[op1Name] as PolicyOperatorDefinition | undefined;
					const op2Def = operators[op2Name] as PolicyOperatorDefinition | undefined;

					if (!op1Def || !op2Def) continue;

					const op1Entry = opMap.get(op1Name);
					const op2Entry = opMap.get(op2Name);
					if (!op1Entry || !op2Entry) continue;
					const val1 = op1Entry.values[op1Entry.values.length - 1];
					const val2 = op2Entry.values[op2Entry.values.length - 1];

					// Check both directions — canCombineWith is not guaranteed symmetric
					if (
						!op1Def.canCombineWith(op2Name, val1, val2) ||
						!op2Def.canCombineWith(op1Name, val2, val1)
					) {
						warnings.push({
							entityType,
							field,
							op1: op1Name,
							op2: op2Name,
							message: `'${op1Name}' cannot combine with '${op2Name}' on field '${field}'`,
						});
						conflictFields.add(fieldKey);
					}
				}
			}
		}

		return { warnings, conflictFields };
	}, [policyLevels]);
}
