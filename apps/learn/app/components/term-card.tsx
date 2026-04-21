import { Card, CardDescription, CardHeader, CardPanel, CardTitle } from "@oidfed/ui";

export function TermCard({
	term,
	section,
	children,
}: {
	term: string;
	section?: string;
	children: React.ReactNode;
}) {
	return (
		<Card className="my-4">
			<CardHeader>
				<CardTitle className="text-base font-semibold">{term}</CardTitle>
				{section && <CardDescription className="text-xs">{section}</CardDescription>}
			</CardHeader>
			<CardPanel className="pt-0 text-sm">{children}</CardPanel>
		</Card>
	);
}
