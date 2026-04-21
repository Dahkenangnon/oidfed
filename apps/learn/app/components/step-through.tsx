import { Badge, Button, Card, CardPanel } from "@oidfed/ui";
import { ChevronLeft, ChevronRight, RotateCcw } from "lucide-react";
import { useState } from "react";

export interface Step {
	title: string;
	content: React.ReactNode;
}

export function StepThrough({ steps }: { steps: Step[] }) {
	const [current, setCurrent] = useState(0);

	return (
		<Card className="my-6">
			<div className="flex items-center justify-between px-4 pt-4">
				<Badge variant="secondary">
					Step {current + 1} of {steps.length}
				</Badge>
				<h4 className="text-sm font-semibold">{steps[current]?.title}</h4>
				<div className="flex gap-1">
					<Button
						variant="ghost"
						size="icon-sm"
						onClick={() => setCurrent((c) => Math.max(0, c - 1))}
						disabled={current === 0}
					>
						<ChevronLeft className="size-4" />
					</Button>
					<Button
						variant="ghost"
						size="icon-sm"
						onClick={() => setCurrent((c) => Math.min(steps.length - 1, c + 1))}
						disabled={current === steps.length - 1}
					>
						<ChevronRight className="size-4" />
					</Button>
					<Button variant="ghost" size="icon-sm" onClick={() => setCurrent(0)}>
						<RotateCcw className="size-3.5" />
					</Button>
				</div>
			</div>
			<CardPanel>{steps[current]?.content}</CardPanel>
		</Card>
	);
}
