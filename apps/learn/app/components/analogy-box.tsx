import { Alert, AlertDescription, AlertTitle } from "@oidfed/ui";
import { Lightbulb } from "lucide-react";

export function AnalogyBox({
	title = "Real-World Analogy",
	children,
}: {
	title?: string;
	children: React.ReactNode;
}) {
	return (
		<Alert variant="info" className="my-6">
			<Lightbulb className="size-4" />
			<AlertTitle>{title}</AlertTitle>
			<AlertDescription>{children}</AlertDescription>
		</Alert>
	);
}
