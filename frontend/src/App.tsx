import { useState } from "react";
import { NavLink, Route, Routes } from "react-router-dom";
import {
  BellRing,
  FileText,
  Gauge,
  ListChecks,
  PanelLeftClose,
  PanelLeftOpen,
  Settings,
  Target as TargetIcon,
} from "lucide-react";
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

function TopBar() {
  return (
    <header className="topbar">
      <div className="topbar-left" />

      <div className="topbar-right">
        <ToolStatusGroup compact showLabels={true} />
        <div className="topbar-divider" />
        <Bell />
      </div>
    </header>
  );
}

export default function App() {
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

  return (
    <ToastProvider>
      <div className={`shell ${collapsed ? "rail-collapsed" : ""}`}>
        <aside className={`rail ${collapsed ? "collapsed" : ""}`} aria-label="Main Navigation">
          <div className="brand">
            <div
              className="brand-main"
              onClick={collapsed ? toggleSidebar : undefined}
              style={collapsed ? { cursor: "pointer" } : undefined}
              title={collapsed ? "Expand sidebar" : undefined}
            >
              <svg viewBox="0 0 32 32" width="28" height="28" aria-hidden className="brand-logo">
                <rect width="32" height="32" rx="8" fill="#1d2840" />
                <circle cx="11.5" cy="16" r="4.6" fill="#e8edf6" />
                <circle cx="20.5" cy="16" r="4.6" fill="#e8edf6" />
                <circle cx="16" cy="16" r="4.6" fill="#5b7cff" />
              </svg>
              {!collapsed && (
                <div className="brand-meta">
                  <span className="brand-name">buns</span>
                  <span className="brand-sub">security assessment</span>
                </div>
              )}
            </div>
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
            {NAV.map(({ to, label, icon: Icon, end }) => (
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
                {!collapsed && <span className="rail-link-label">{label}</span>}
              </NavLink>
            ))}
          </nav>
        </aside>

        <div className="workspace">
          <TopBar />
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
              <Route path="*" element={<p className="pad">This page does not exist.</p>} />
            </Routes>
          </main>
        </div>
      </div>
    </ToastProvider>
  );
}
