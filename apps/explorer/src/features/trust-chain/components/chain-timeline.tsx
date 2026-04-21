import type { ValidatedTrustChain, ValidationError } from "@oidfed/core";
import { ChainStep } from "./chain-step";

interface ChainTimelineProps {
	readonly chain: ValidatedTrustChain;
	readonly errors: readonly ValidationError[];
}

export function ChainTimeline({ chain, errors }: ChainTimelineProps) {
	const { statements } = chain;

	const signatureErrorIndices = new Set(
		errors.filter((e) => e.statementIndex !== undefined).map((e) => e.statementIndex as number),
	);

	return (
		<div className="flex flex-col">
			{statements.map((stmt, i) => (
				<div
					// biome-ignore lint/suspicious/noArrayIndexKey: statements ordered by chain position
					key={`stmt-${i}-${stmt.payload.iss}-${stmt.payload.sub}`}
				>
					{i > 0 && (
						<div className="flex pl-[22px] py-0.5">
							<svg
								width="12"
								height="14"
								viewBox="0 0 12 14"
								className="text-muted-foreground"
								fill="none"
								stroke="currentColor"
								strokeWidth="1.5"
								strokeLinecap="round"
								strokeLinejoin="round"
								aria-hidden="true"
							>
								<line x1="6" y1="0" x2="6" y2="10" />
								<polyline points="2,7 6,11 10,7" />
							</svg>
						</div>
					)}
					<ChainStep
						statement={stmt}
						index={i}
						total={statements.length}
						signatureValid={!signatureErrorIndices.has(i)}
					/>
				</div>
			))}
		</div>
	);
}
