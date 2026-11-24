import { NavLink, Route, Routes } from "react-router-dom";
import { api } from "./api";
import { usePoll } from "./components/ui";
import Overview from "./pages/Overview";
import Targets from "./pages/Targets";
import TargetDetail from "./pages/TargetDetail";
import ScanView from "./pages/ScanView";
import Findings from "./pages/Findings";
import Review from "./pages/Review";
import Reports from "./pages/Reports";

function Health() {
  const { data, error } = usePoll(api.health, [], () => true, 15000);
  if (error) return <div className="health"><p className="health-row bad">Backend unreachable</p></div>;
  if (!data) return null;
  const zapOk = data.zap !== "unreachable";
  return (
    <div className="health" aria-label="Tool status">
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
        {data.ai_mode === "deepseek" ? data.ai_model : "Offline rules (no AI key)"}
      </p>
    </div>
  );
}

export default function App() {
  return (
    <div className="shell">
      <aside className="rail">
        <div className="brand">
          <svg viewBox="0 0 32 32" width="26" height="26" aria-hidden>
            <circle cx="11" cy="16" r="5" fill="currentColor" />
            <circle cx="21" cy="16" r="5" fill="currentColor" />
            <circle cx="16" cy="16" r="5" fill="var(--action)" />
          </svg>
          <span>buns</span>
        </div>
        <nav>
          <NavLink to="/" end>Overview</NavLink>
          <NavLink to="/findings">Findings</NavLink>
          <NavLink to="/targets">Targets</NavLink>
          <NavLink to="/reports">Reports</NavLink>
        </nav>
        <Health />
      </aside>
      <main className="main">
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/targets" element={<Targets />} />
          <Route path="/targets/:id" element={<TargetDetail />} />
          <Route path="/scans/:id" element={<ScanView />} />
          <Route path="/findings" element={<Findings />} />
          <Route path="/findings/:id" element={<Review />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="*" element={<p className="pad">This page does not exist.</p>} />
        </Routes>
      </main>
    </div>
  );
}
