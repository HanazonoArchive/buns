import { useEffect, useRef, useState, type ReactNode } from "react";
import { NavLink, Route, Routes, useLocation } from "react-router-dom";
import {
  BellRing,
  FileText,
  Gauge,
  ListChecks,
  PanelLeftClose,
  PanelLeftOpen,
  ScrollText,
  Settings,
  Target as TargetIcon,
  UsersRound,
} from "lucide-react";
import { AuthGate, useAuth } from "./auth";
import { ChangePassword } from "./components/ChangePassword";
import { Logo } from "./components/Logo";
import { UserMenu } from "./components/UserMenu";
import Login from "./pages/Login";
import Users from "./pages/Users";
import Logs from "./pages/Logs";
import { ToastProvider } from "./components/toast";
import { ToolStatusGroup } from "./components/ToolStatus";
import Bell from "./components/Bell";
import Overview from "./pages/Overview";
import Targets from "./pages/Targets";
import TargetDetail from "./pages/TargetDetail";
import ScanView from "./pages/ScanView";
import Findings from "./pages/Findings";
import Review from "./pages/Review";
import Reports from "./pages/Reports";
import SettingsPage from "./pages/Settings";
import Notifications from "./pages/Notifications";

const NAV = [
  { to: "/", label: "Overview", icon: Gauge, end: true },
  { to: "/findings", label: "Findings", icon: ListChecks },
  { to: "/targets", label: "Targets", icon: TargetIcon },
  { to: "/reports", label: "Reports", icon: FileText },
  { to: "/notifications", label: "Alerts", icon: BellRing },
  { to: "/settings", label: "Settings", icon: Settings },
];

const ADMIN_NAV = [
  { to: "/users", label: "Users", icon: UsersRound },
  { to: "/logs", label: "Logs", icon: ScrollText },
];

function TopBar() {
  return (
    <header className="topbar">
      <div className="topbar-left" />

      <div className="topbar-right">
        <ToolStatusGroup compact showLabels={true} />
        <div className="topbar-divider" />
        <Bell />
        <div className="topbar-divider" />
        <UserMenu />
      </div>
    </header>
  );
}

/** Only the content area scrolls; send it back to the top on navigation. */
function Scroller({ children }: { children: ReactNode }) {
  const ref = useRef<HTMLDivElement>(null);
  const { pathname } = useLocation();
  useEffect(() => {
    ref.current?.scrollTo({ top: 0 });
  }, [pathname]);
  return (
    <div className="scroller" ref={ref}>
      {children}
    </div>
  );
}

export default function App() {
  return (
    <ToastProvider>
      <AuthGate signedOut={(onSignedIn) => <Login onSignedIn={onSignedIn} />}>
        <Shell />
      </AuthGate>
    </ToastProvider>
  );
}

function AdminOnly() {
  return <p className="pad dim">Only the superadmin (sadmin@buns.com) can open this page.</p>;
}

function Shell() {
  const { me, isSuperadmin } = useAuth();
  const [collapsed, setCollapsed] = useState<boolean>(() => {
    try {
      return localStorage.getItem("buns_sidebar_collapsed") === "true";
    } catch {
      return false;
    }
  });

  const toggleSidebar = () => {
    setCollapsed((prev) => {
      const next = !prev;
      try {
        localStorage.setItem("buns_sidebar_collapsed", String(next));
      } catch {
        /* storage not available */
      }
      return next;
    });
  };

  const link = ({ to, label, icon: Icon, end }: { to: string; label: string; icon: typeof Gauge; end?: boolean }) => (
    <NavLink
      key={to}
      to={to}
      end={end}
      className={({ isActive }) => `rail-link ${isActive ? "active" : ""}`}
      title={collapsed ? label : undefined}
    >
      <span className="rail-link-icon">
        <Icon size={18} strokeWidth={2} aria-hidden />
      </span>
      <span className="rail-link-label">{label}</span>
    </NavLink>
  );

  return (
    <>
      <div className={`shell ${collapsed ? "rail-collapsed" : ""}`}>
        <aside className={`rail ${collapsed ? "collapsed" : ""}`} aria-label="Main Navigation">
          <div className="brand">
            {!collapsed && (
              <div className="brand-main">
                <Logo />
                <div className="brand-meta">
                  <span className="brand-name">buns</span>
                  <span className="brand-sub">security assessment</span>
                </div>
              </div>
            )}
            <button
              type="button"
              className="rail-toggle-btn"
              onClick={toggleSidebar}
              aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
              title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            >
              {collapsed ? <PanelLeftOpen size={17} /> : <PanelLeftClose size={17} />}
            </button>
          </div>

          <nav className="rail-nav">
            {NAV.map(link)}
            {isSuperadmin && (
              <>
                <div className="rail-group">{!collapsed && "Administration"}</div>
                {ADMIN_NAV.map(link)}
              </>
            )}
          </nav>
        </aside>

        <div className="workspace">
          <TopBar />
          <Scroller>
          {me.must_change_password ? null : (
          <main className="main">
            <Routes>
              <Route path="/" element={<Overview />} />
              <Route path="/targets" element={<Targets />} />
              <Route path="/targets/:id" element={<TargetDetail />} />
              <Route path="/scans/:id" element={<ScanView />} />
              <Route path="/findings" element={<Findings />} />
              <Route path="/findings/:id" element={<Review />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="/notifications" element={<Notifications />} />
              <Route path="/settings" element={<SettingsPage />} />
              <Route path="/users" element={isSuperadmin ? <Users /> : <AdminOnly />} />
              <Route path="/logs" element={isSuperadmin ? <Logs /> : <AdminOnly />} />
              <Route path="*" element={<p className="pad">This page does not exist.</p>} />
            </Routes>
          </main>
          )}
          </Scroller>
        </div>
      </div>
      {me.must_change_password && <ChangePassword forced />}
    </>
  );
}
