export function downloadJson(data: unknown, filename: string): void {
	const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
	downloadBlob(blob, filename);
}

export function downloadText(text: string, filename: string, mimeType = "text/plain"): void {
	const blob = new Blob([text], { type: mimeType });
	downloadBlob(blob, filename);
}

export function downloadBlob(blob: Blob, filename: string): void {
	const url = URL.createObjectURL(blob);
	const a = document.createElement("a");
	a.href = url;
	a.download = filename;
	document.body.appendChild(a);
	a.click();
	document.body.removeChild(a);
	URL.revokeObjectURL(url);
}
