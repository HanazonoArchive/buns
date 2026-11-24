import { Bot, Sparkles, Zap, Terminal, XCircle, Cpu } from "lucide-react";
import { api } from "../api";
import { usePoll } from "./ui";

export function ToolStatusGroup({ compact = true }: { compact?: boolean; showLabels?: boolean }) {
  const { data, error } = usePoll(api.health, [], () => true, 15000);

  if (error) {
    return (
      <div className={`tool-status-group ${compact ? "compact" : ""}`}>
        <div className="status-badge status-badge-bad" tabIndex={0} aria-label="Backend Offline">
          <XCircle size={15} />
          <div className="status-tooltip" role="tooltip">
            <span className="status-tooltip-title">Backend Offline</span>
            <span className="status-tooltip-sub">Server unreachable</span>
          </div>
        </div>
      </div>
    );
  }

  if (!data) {
    return (
      <div className={`tool-status-group ${compact ? "compact" : ""}`}>
        <div className="status-badge status-badge-loading">
          <Cpu size={15} className="spin" />
        </div>
      </div>
    );
  }

  const zapOk = data.zap !== "unreachable";
  const isDeepSeek = data.ai_mode === "deepseek";

  return (
    <div className={`tool-status-group ${compact ? "compact" : ""}`} role="region" aria-label="System Tools & AI Status">
      {/* AI Engine Status Badge */}
      <div
        className={`status-badge status-btn-ai ${isDeepSeek ? "online" : "mode-rules"}`}
        tabIndex={0}
        aria-label={isDeepSeek ? "AI Supported" : "Heuristic Rules Active"}
      >
        {isDeepSeek ? <Bot size={15} strokeWidth={2.2} /> : <Sparkles size={15} strokeWidth={2.2} />}
        <div className="status-tooltip" role="tooltip">
          <div className="status-tooltip-header">
            <span className="status-tooltip-dot dot-green" />
            <span className="status-tooltip-title">{isDeepSeek ? "AI Supported" : "Rules Active"}</span>
          </div>
          <span className="status-tooltip-sub">
            {isDeepSeek ? (data.ai_model || "DeepSeek LLM") : "Heuristic Engine"}
          </span>
        </div>
      </div>

      {/* ZAP Status Badge */}
      <div
        className={`status-badge status-btn-zap ${zapOk ? "online" : "offline"}`}
        tabIndex={0}
        aria-label={zapOk ? "ZAP Active" : "ZAP Inactive"}
      >
        <Zap size={15} strokeWidth={2.2} />
        <div className="status-tooltip" role="tooltip">
          <div className="status-tooltip-header">
            <span className={`status-tooltip-dot dot-${zapOk ? "green" : "slate"}`} />
            <span className="status-tooltip-title">{zapOk ? "ZAP Active" : "ZAP Inactive"}</span>
          </div>
          <span className="status-tooltip-sub">{zapOk ? data.zap : "Not connected"}</span>
        </div>
      </div>

      {/* cURL Engine Status Badge */}
      <div
        className={`status-badge status-btn-curl ${data.curl ? "online" : "offline"}`}
        tabIndex={0}
        aria-label={data.curl ? "cURL Active" : "cURL Inactive"}
      >
        <Terminal size={15} strokeWidth={2.2} />
        <div className="status-tooltip" role="tooltip">
          <div className="status-tooltip-header">
            <span className={`status-tooltip-dot dot-${data.curl ? "green" : "slate"}`} />
            <span className="status-tooltip-title">{data.curl ? "cURL Active" : "cURL Inactive"}</span>
          </div>
          <span className="status-tooltip-sub">{data.curl ? "Probing ready" : "Executable missing"}</span>
        </div>
      </div>
    </div>
  );
}
