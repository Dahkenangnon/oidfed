import { Tabs, TabsContent, TabsList, TabsTrigger } from "@oidfed/ui";
import { useState } from "react";
import { decodeJwtPart } from "@/lib/jwt";
import { CodeBlock } from "./code-block";
import { CopyButton } from "./copy-button";

interface JwtViewerProps {
	readonly jwt: string;
	readonly contentType?: string | undefined;
}

export function JwtViewer({ jwt, contentType }: JwtViewerProps) {
	const [activeTab, setActiveTab] = useState("decoded");
	const parts = jwt.split(".");
	const header = parts[0] ? decodeJwtPart(parts[0]) : null;
	const payload = parts[1] ? decodeJwtPart(parts[1]) : null;

	return (
		<div className="space-y-4">
			{contentType != null && (
				<p className="text-xs text-muted-foreground font-mono">{contentType}</p>
			)}
			<Tabs value={activeTab} onValueChange={setActiveTab}>
				<TabsList>
					<TabsTrigger value="decoded">Decoded</TabsTrigger>
					<TabsTrigger value="raw">Raw JWT</TabsTrigger>
				</TabsList>
				<TabsContent value="decoded" className="space-y-4">
					{header != null && (
						<div>
							<h4 className="mb-2 text-xs font-medium text-muted-foreground uppercase tracking-wide">
								Header
							</h4>
							<CodeBlock code={JSON.stringify(header, null, 2)} />
						</div>
					)}
					{payload != null && (
						<div>
							<h4 className="mb-2 text-xs font-medium text-muted-foreground uppercase tracking-wide">
								Payload
							</h4>
							<CodeBlock code={JSON.stringify(payload, null, 2)} />
						</div>
					)}
				</TabsContent>
				<TabsContent value="raw">
					<div className="relative rounded-lg border bg-code p-4">
						<CopyButton value={jwt} className="absolute right-2 top-2 size-7" />
						<pre className="overflow-auto text-xs font-mono break-all whitespace-pre-wrap">
							<span className="text-blue-400">{parts[0]}</span>
							<span className="text-code-foreground">.</span>
							<span className="text-purple-400">{parts[1]}</span>
							<span className="text-code-foreground">.</span>
							<span className="text-amber-400">{parts[2]}</span>
						</pre>
					</div>
				</TabsContent>
			</Tabs>
		</div>
	);
}
