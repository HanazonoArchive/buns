import { NavLink, Route, Routes } from "react-router-dom";
import { BellRing, FileText, Gauge, ListChecks, Settings, Target as TargetIcon } from "lucide-react";
import { api } from "./api";
import { usePoll } from "./components/ui";
import { ToastProvider } from "./components/toast";
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

function Health() {
  const { data, error } = usePoll(api.health, [], () => true, 15000);
  if (error)
    return (
      <div className="health">
        <p className="health-row bad"><i />Backend unreachable</p>
      </div>
    );
  if (!data) return null;
  const zapOk = data.zap !== "unreachable";
  return (
    <div className="health" aria-label="Tool status">
      <p className="health-title">Tools</p>
      <p className={`health-row ${zapOk ? "ok" : "bad"}`} title={zapOk ? data.zap : "Scans will run cURL probes only"}>
        <i />
        {zapOk ? data.zap : "ZAP not connected"}
      </p>
      <p className={`health-row ${data.curl ? "ok" : "bad"}`}>
        <i />
        {data.curl ? "cURL ready" : "cURL missing"}
      </p>
      <p
        className={`health-row ${data.ai_mode === "deepseek" ? "ok" : "warn"}`}
        title={data.ai_mode === "deepseek" ? "" : "Set DEEPSEEK_API_KEY to use the model; the built-in rules engine is used meanwhile"}
      >
        <i />
        {data.ai_mode === "deepseek" ? data.ai_model : "Offline rules"}
      </p>
    </div>
  );
}

const NAV = [
  { to: "/", label: "Overview", icon: Gauge, end: true },
  { to: "/findings", label: "Findings", icon: ListChecks },
  { to: "/targets", label: "Targets", icon: TargetIcon },
  { to: "/reports", label: "Reports", icon: FileText },
  { to: "/notifications", label: "Alerts", icon: BellRing },
  { to: "/settings", label: "Settings", icon: Settings },
];

function TopBar() {
  const { data: targets } = usePoll(api.targets, [], () => false);
  const t = targets?.length === 1 ? targets[0] : null;
  return (
    <div className="topbar">
      {t ? (
        <span className="topbar-ctx">
          <i className="live" aria-hidden />
          Testing <b>{t.name}</b> <span className="mono">{t.base_url}</span>
        </span>
      ) : targets && targets.length > 1 ? (
        <span className="topbar-ctx">{targets.length} targets registered</span>
      ) : (
        <span />
      )}
      <div className="topbar-right">
        <Bell />
      </div>
    </div>
  );
}

export default function App() {
  return (
    <ToastProvider>
      <div className="shell">
        <aside className="rail">
          <div className="brand">
            <svg viewBox="0 0 32 32" width="28" height="28" aria-hidden>
              <rect width="32" height="32" rx="8" fill="#1d2840" />
              <circle cx="11.5" cy="16" r="4.6" fill="#e8edf6" />
              <circle cx="20.5" cy="16" r="4.6" fill="#e8edf6" />
              <circle cx="16" cy="16" r="4.6" fill="#5b7cff" />
            </svg>
            <span className="brand-name">buns</span>
            <span className="brand-sub">security assessment</span>
          </div>
          <nav>
            {NAV.map(({ to, label, icon: Icon, end }) => (
              <NavLink key={to} to={to} end={end}>
                <Icon size={17} strokeWidth={1.9} aria-hidden />
                {label}
              </NavLink>
            ))}
          </nav>
          <Health />
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
