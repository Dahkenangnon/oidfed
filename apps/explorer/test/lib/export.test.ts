import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { downloadJson, downloadText } from "@/lib/export";

// jsdom doesn't provide URL.createObjectURL/revokeObjectURL
if (typeof URL.createObjectURL !== "function") {
	URL.createObjectURL = () => "blob:stub";
}
if (typeof URL.revokeObjectURL !== "function") {
	URL.revokeObjectURL = () => {};
}

describe("downloadJson", () => {
	let anchorClicked: boolean;
	let anchorHref: string;
	let anchorDownload: string;

	beforeEach(() => {
		anchorClicked = false;
		anchorHref = "";
		anchorDownload = "";

		vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:mock-url");
		vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {});
		vi.spyOn(document.body, "appendChild").mockImplementation((node) => node);
		vi.spyOn(document.body, "removeChild").mockImplementation((node) => node);
		vi.spyOn(document, "createElement").mockReturnValue({
			set href(v: string) {
				anchorHref = v;
			},
			get href() {
				return anchorHref;
			},
			set download(v: string) {
				anchorDownload = v;
			},
			get download() {
				return anchorDownload;
			},
			click() {
				anchorClicked = true;
			},
		} as unknown as HTMLAnchorElement);
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("creates a JSON blob and triggers download", () => {
		const data = { key: "value" };
		downloadJson(data, "test.json");

		expect(URL.createObjectURL).toHaveBeenCalledWith(expect.any(Blob));
		const blob = (URL.createObjectURL as ReturnType<typeof vi.fn>).mock.calls[0][0] as Blob;
		expect(blob.type).toBe("application/json");
		expect(anchorDownload).toBe("test.json");
		expect(anchorClicked).toBe(true);
		expect(URL.revokeObjectURL).toHaveBeenCalledWith("blob:mock-url");
	});
});

describe("downloadText", () => {
	let anchorClicked: boolean;
	let anchorDownload: string;

	beforeEach(() => {
		anchorClicked = false;
		anchorDownload = "";

		vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:mock-url");
		vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {});
		vi.spyOn(document.body, "appendChild").mockImplementation((node) => node);
		vi.spyOn(document.body, "removeChild").mockImplementation((node) => node);
		vi.spyOn(document, "createElement").mockReturnValue({
			set href(_v: string) {
				/* noop */
			},
			set download(v: string) {
				anchorDownload = v;
			},
			get download() {
				return anchorDownload;
			},
			click() {
				anchorClicked = true;
			},
		} as unknown as HTMLAnchorElement);
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("creates a text blob with custom MIME type", () => {
		downloadText("digraph {}", "graph.dot", "text/vnd.graphviz");

		const blob = (URL.createObjectURL as ReturnType<typeof vi.fn>).mock.calls[0][0] as Blob;
		expect(blob.type).toBe("text/vnd.graphviz");
		expect(anchorDownload).toBe("graph.dot");
		expect(anchorClicked).toBe(true);
	});

	it("defaults to text/plain MIME type", () => {
		downloadText("hello", "out.txt");

		const blob = (URL.createObjectURL as ReturnType<typeof vi.fn>).mock.calls[0][0] as Blob;
		expect(blob.type).toBe("text/plain");
	});
});
