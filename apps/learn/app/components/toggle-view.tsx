import { Button } from "@oidfed/ui";
import { useState } from "react";

export function ToggleView({
	labelA,
	labelB,
	contentA,
	contentB,
}: {
	labelA: string;
	labelB: string;
	contentA: React.ReactNode;
	contentB: React.ReactNode;
}) {
	const [showB, setShowB] = useState(false);

	return (
		<div className="my-6">
			<div className="flex gap-2 mb-4">
				<Button variant={!showB ? "default" : "outline"} size="sm" onClick={() => setShowB(false)}>
					{labelA}
				</Button>
				<Button variant={showB ? "default" : "outline"} size="sm" onClick={() => setShowB(true)}>
					{labelB}
				</Button>
			</div>
			{showB ? contentB : contentA}
		</div>
	);
}
