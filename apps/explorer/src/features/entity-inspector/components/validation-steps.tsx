import { Card, CardContent, CardHeader, CardTitle } from "@oidfed/ui";
import { ClipboardCheck } from "lucide-react";
import { ValidationBadge } from "@/components/shared/validation-badge";

interface ValidationStepsProps {
	readonly header: Record<string, unknown>;
	readonly payload: Record<string, unknown>;
	readonly schemaErrors: readonly string[];
}

interface StepResult {
	readonly label: string;
	readonly status: "pass" | "fail" | "warn";
	readonly detail?: string;
}

function runValidationSteps(
	header: Record<string, unknown>,
	payload: Record<string, unknown>,
	schemaErrors: readonly string[],
): StepResult[] {
	const steps: StepResult[] = [];

	// 1. JWT structure (3 parts)
	steps.push({ label: "Valid JWT structure", status: "pass" });

	// 2. typ header
	const typ = header.typ;
	steps.push(
		typ === "entity-statement+jwt"
			? { label: "typ header is entity-statement+jwt", status: "pass" }
			: {
					label: "typ header",
					status: typ ? "warn" : "fail",
					detail: `typ=${String(typ ?? "missing")}`,
				},
	);

	// 3. alg header
	const alg = header.alg;
	const validAlgs = [
		"RS256",
		"RS384",
		"RS512",
		"ES256",
		"ES384",
		"ES512",
		"PS256",
		"PS384",
		"PS512",
	];
	steps.push(
		typeof alg === "string" && validAlgs.includes(alg)
			? { label: `Algorithm: ${alg}`, status: "pass" }
			: { label: "Algorithm", status: "fail", detail: `alg=${String(alg ?? "missing")}` },
	);

	// 4. kid header
	steps.push(
		header.kid
			? { label: "kid present in header", status: "pass" }
			: { label: "kid missing from header", status: "fail" },
	);

	// 5. iss claim
	steps.push(
		typeof payload.iss === "string" && payload.iss.length > 0
			? { label: "iss claim present", status: "pass" }
			: { label: "iss claim missing", status: "fail" },
	);

	// 6. sub claim
	steps.push(
		typeof payload.sub === "string" && payload.sub.length > 0
			? { label: "sub claim present", status: "pass" }
			: { label: "sub claim missing", status: "fail" },
	);

	// 7. iss === sub (entity configuration)
	steps.push(
		payload.iss === payload.sub
			? { label: "iss === sub (self-signed)", status: "pass" }
			: { label: "iss !== sub", status: "warn", detail: "May be a subordinate statement" },
	);

	// 8. iat claim
	const iat = payload.iat;
	steps.push(
		typeof iat === "number" && iat > 0
			? { label: "iat claim valid", status: "pass" }
			: { label: "iat claim", status: "fail", detail: `iat=${String(iat ?? "missing")}` },
	);

	// 9. exp claim
	const exp = payload.exp;
	const now = Math.floor(Date.now() / 1000);
	if (typeof exp === "number") {
		steps.push(
			exp > now
				? { label: "exp claim valid (not expired)", status: "pass" }
				: {
						label: "exp claim expired",
						status: "fail",
						detail: `Expired ${new Date(exp * 1000).toISOString()}`,
					},
		);
	} else {
		steps.push({ label: "exp claim missing", status: "fail" });
	}

	// 10. jwks claim
	const jwks = payload.jwks;
	steps.push(
		jwks && typeof jwks === "object" && Array.isArray((jwks as Record<string, unknown>).keys)
			? { label: "jwks claim present with keys", status: "pass" }
			: { label: "jwks claim", status: "fail", detail: "Missing or invalid" },
	);

	// 11. Schema validation
	steps.push(
		schemaErrors.length === 0
			? { label: "Schema validation passed", status: "pass" }
			: {
					label: "Schema validation errors",
					status: "fail",
					detail: `${schemaErrors.length} issue(s)`,
				},
	);

	// 12. metadata present (at least one entity type)
	const metadata = payload.metadata;
	steps.push(
		metadata && typeof metadata === "object" && Object.keys(metadata).length > 0
			? { label: "Metadata contains entity type(s)", status: "pass" }
			: { label: "No metadata entity types", status: "warn" },
	);

	return steps;
}

export function ValidationSteps({ header, payload, schemaErrors }: ValidationStepsProps) {
	const steps = runValidationSteps(header, payload, schemaErrors);
	const passCount = steps.filter((s) => s.status === "pass").length;

	return (
		<Card>
			<CardHeader>
				<CardTitle className="flex items-center gap-2 text-sm">
					<ClipboardCheck className="size-4" />
					Validation ({passCount}/{steps.length} passed)
				</CardTitle>
			</CardHeader>
			<CardContent>
				<ul className="space-y-2">
					{steps.map((step) => (
						<li key={step.label} className="flex items-start gap-2">
							<ValidationBadge status={step.status} />
							<div>
								<span className="text-sm">{step.label}</span>
								{step.detail && <p className="text-xs text-muted-foreground">{step.detail}</p>}
							</div>
						</li>
					))}
				</ul>
			</CardContent>
		</Card>
	);
}
