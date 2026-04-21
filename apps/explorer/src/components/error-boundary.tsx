import { Component, type ErrorInfo, type ReactNode } from "react";

interface Props {
	readonly children: ReactNode;
}

interface State {
	readonly hasError: boolean;
	readonly error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
	constructor(props: Props) {
		super(props);
		this.state = { hasError: false, error: null };
	}

	static getDerivedStateFromError(error: Error): State {
		return { hasError: true, error };
	}

	componentDidCatch(error: Error, info: ErrorInfo): void {
		console.error("Uncaught error:", error, info.componentStack);
	}

	render(): ReactNode {
		if (this.state.hasError) {
			return (
				<div className="flex min-h-screen items-center justify-center p-8">
					<div className="max-w-lg space-y-4 text-center">
						<h1 className="text-2xl font-semibold">Something went wrong</h1>
						<p className="text-sm text-muted-foreground">
							{this.state.error?.message ?? "An unexpected error occurred."}
						</p>
						<button
							type="button"
							className="rounded-md bg-primary px-4 py-2 text-sm text-primary-foreground"
							onClick={() => window.location.reload()}
						>
							Reload page
						</button>
					</div>
				</div>
			);
		}
		return this.props.children;
	}
}
