import { Card, CardContent } from "@oidfed/ui";
import { Construction } from "lucide-react";

interface ComingSoonPageProps {
	readonly title: string;
}

export function ComingSoonPage({ title }: ComingSoonPageProps) {
	return (
		<div className="flex items-center justify-center min-h-[60vh]">
			<Card className="max-w-md w-full">
				<CardContent className="flex flex-col items-center gap-4 py-12">
					<Construction className="size-12 text-muted-foreground" />
					<h1 className="text-xl font-semibold">{title}</h1>
					<p className="text-sm text-muted-foreground text-center">
						This feature is coming in a future release.
					</p>
				</CardContent>
			</Card>
		</div>
	);
}
