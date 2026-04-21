import {
	Separator,
	Sidebar,
	SidebarContent,
	SidebarFooter,
	SidebarGroup,
	SidebarGroupContent,
	SidebarGroupLabel,
	SidebarHeader,
	SidebarMenu,
	SidebarMenuButton,
	SidebarMenuItem,
	Tooltip,
	TooltipPopup,
	TooltipTrigger,
	useSidebar,
} from "@oidfed/ui";
import {
	BadgeCheck,
	BookOpen,
	Clock,
	ExternalLink,
	FileSearch,
	FlaskConical,
	GitCompare,
	Github,
	Globe,
	HeartPulse,
	Link,
	List,
	PanelLeftClose,
	PanelLeftOpen,
	Route,
	Settings,
} from "lucide-react";
import { useLocation, useNavigate } from "react-router";

interface NavItem {
	readonly label: string;
	readonly path: string;
	readonly icon: React.ComponentType<{ className?: string }>;
	readonly disabled: boolean;
}

const navItems: readonly NavItem[] = [
	{ label: "Entity Inspector", path: "/entity", icon: FileSearch, disabled: false },
	{ label: "Trust Chain", path: "/chain", icon: Link, disabled: false },
	{ label: "Topology Graph", path: "/topology", icon: Globe, disabled: false },
	{ label: "Subordinates", path: "/subordinates", icon: List, disabled: false },
	{ label: "Expiration", path: "/expiry", icon: Clock, disabled: false },
	{ label: "Trust Marks", path: "/trust-marks", icon: BadgeCheck, disabled: false },
	{ label: "Policy Simulator", path: "/policy", icon: FlaskConical, disabled: false },
	{ label: "Health Check", path: "/health", icon: HeartPulse, disabled: false },
	{ label: "Resolve Proxy", path: "/resolve", icon: Route, disabled: false },
	{ label: "Metadata Diff", path: "/diff", icon: GitCompare, disabled: false },
];

export function AppSidebar() {
	const location = useLocation();
	const navigate = useNavigate();
	const { state, toggleSidebar } = useSidebar();
	const isCollapsed = state === "collapsed";

	return (
		<Sidebar collapsible="icon">
			<SidebarHeader>
				<SidebarMenu>
					<SidebarMenuItem>
						<div className="flex items-center gap-1">
							<SidebarMenuButton
								size="lg"
								onClick={() => navigate("/")}
								className="cursor-pointer flex-1"
							>
								<div className="flex size-8 items-center justify-center rounded-lg bg-brand-500 text-white shrink-0">
									<Globe className="size-4" />
								</div>
								<div className="flex flex-col gap-0.5 leading-none">
									<span className="font-semibold">OidFed Explorer</span>
									<span className="text-xs text-muted-foreground">v0.1.0</span>
								</div>
							</SidebarMenuButton>
							{!isCollapsed && (
								<Tooltip>
									<TooltipTrigger
										render={
											<button
												type="button"
												onClick={toggleSidebar}
												className="flex size-8 items-center justify-center rounded-md text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground shrink-0"
											/>
										}
									>
										<PanelLeftClose className="size-4" />
									</TooltipTrigger>
									<TooltipPopup>Collapse sidebar</TooltipPopup>
								</Tooltip>
							)}
						</div>
					</SidebarMenuItem>
					{isCollapsed && (
						<SidebarMenuItem>
							<Tooltip>
								<TooltipTrigger
									render={
										<button
											type="button"
											onClick={toggleSidebar}
											className="flex size-8 items-center justify-center rounded-md text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground w-full"
										/>
									}
								>
									<PanelLeftOpen className="size-4" />
								</TooltipTrigger>
								<TooltipPopup side="right">Expand sidebar</TooltipPopup>
							</Tooltip>
						</SidebarMenuItem>
					)}
				</SidebarMenu>
			</SidebarHeader>

			<SidebarContent>
				<SidebarGroup>
					<SidebarGroupLabel>Features</SidebarGroupLabel>
					<SidebarGroupContent>
						<SidebarMenu>
							{navItems.map((item) => {
								const isActive = location.pathname.startsWith(item.path);
								const button = (
									<SidebarMenuButton
										data-active={isActive}
										onClick={() => {
											if (!item.disabled) navigate(item.path);
										}}
										className={item.disabled ? "opacity-50 cursor-not-allowed" : "cursor-pointer"}
									>
										<item.icon className="size-4" />
										<span>{item.label}</span>
									</SidebarMenuButton>
								);

								return (
									<SidebarMenuItem key={item.path}>
										{item.disabled && isCollapsed ? (
											<Tooltip>
												<TooltipTrigger render={button} />
												<TooltipPopup side="right">{item.label} — Coming soon</TooltipPopup>
											</Tooltip>
										) : (
											button
										)}
									</SidebarMenuItem>
								);
							})}
						</SidebarMenu>
					</SidebarGroupContent>
				</SidebarGroup>
			</SidebarContent>

			<SidebarFooter>
				<SidebarMenu>
					<SidebarMenuItem>
						<SidebarMenuButton
							data-active={location.pathname === "/settings"}
							onClick={() => navigate("/settings")}
							className="cursor-pointer"
						>
							<Settings className="size-4" />
							<span>Settings</span>
						</SidebarMenuButton>
					</SidebarMenuItem>
					<Separator className="my-1" />
					<SidebarMenuItem>
						<SidebarMenuButton
							render={
								<a
									href="https://oidfed.com"
									target="_blank"
									rel="noopener noreferrer"
									aria-label="oidfed.com — project home"
								/>
							}
						>
							<Globe className="size-4" />
							<span>Home Page</span>
							<ExternalLink className="size-3 ml-auto opacity-50" />
						</SidebarMenuButton>
					</SidebarMenuItem>
					<SidebarMenuItem>
						<SidebarMenuButton
							render={
								<a
									href="https://learn.oidfed.com"
									target="_blank"
									rel="noopener noreferrer"
									aria-label="Learn OpenID Federation"
								/>
							}
						>
							<BookOpen className="size-4" />
							<span>Learn OpenID Federation</span>
							<ExternalLink className="size-3 ml-auto opacity-50" />
						</SidebarMenuButton>
					</SidebarMenuItem>
					<SidebarMenuItem>
						<SidebarMenuButton
							render={
								<a
									href="https://github.com/Dahkenangnon/oidfed"
									target="_blank"
									rel="noopener noreferrer"
									aria-label="OidFed on GitHub"
								/>
							}
						>
							<Github className="size-4" />
							<span>GitHub Repos</span>
							<ExternalLink className="size-3 ml-auto opacity-50" />
						</SidebarMenuButton>
					</SidebarMenuItem>
				</SidebarMenu>
			</SidebarFooter>
		</Sidebar>
	);
}
