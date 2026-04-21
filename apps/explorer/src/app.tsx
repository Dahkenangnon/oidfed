import { HashRouter, Route, Routes } from "react-router";
import { RootLayout } from "./components/layout/root-layout";
import { MetadataDiffPage } from "./features/diff/page";
import { EntityInspectorPage } from "./features/entity-inspector/page";
import { ExpirationDashboardPage } from "./features/expiry/page";
import { HealthCheckPage } from "./features/health/page";
import { HomePage } from "./features/home/page";
import { PolicySimulatorPage } from "./features/policy/page";
import { ResolveProxyPage } from "./features/resolve/page";
import { SettingsPage } from "./features/settings/page";
import { SubordinateListingPage } from "./features/subordinates/page";
import { TopologyGraphPage } from "./features/topology/page";
import { TrustChainPage } from "./features/trust-chain/page";
import { TrustMarkViewerPage } from "./features/trust-marks/page";

export function App() {
	return (
		<HashRouter>
			<Routes>
				<Route element={<RootLayout />}>
					<Route index element={<HomePage />} />
					<Route path="/entity" element={<EntityInspectorPage />} />
					<Route path="/entity/:entityId" element={<EntityInspectorPage />} />
					<Route path="/chain" element={<TrustChainPage />} />
					<Route path="/chain/:entityId" element={<TrustChainPage />} />
					<Route path="/topology" element={<TopologyGraphPage />} />
					<Route path="/subordinates" element={<SubordinateListingPage />} />
					<Route path="/expiry" element={<ExpirationDashboardPage />} />
					<Route path="/trust-marks" element={<TrustMarkViewerPage />} />
					<Route path="/policy" element={<PolicySimulatorPage />} />
					<Route path="/health" element={<HealthCheckPage />} />
					<Route path="/resolve" element={<ResolveProxyPage />} />
					<Route path="/diff" element={<MetadataDiffPage />} />
					<Route path="/settings" element={<SettingsPage />} />
				</Route>
			</Routes>
		</HashRouter>
	);
}
