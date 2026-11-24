export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Category = "authentication" | "access_control" | "injection" | "info_disclosure";
export type ReviewStatus = "pending" | "confirmed" | "rejected";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
export const CATEGORIES: Category[] = ["authentication", "access_control", "injection", "info_disclosure"];

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Informational",
};

export const CATEGORY_LABEL: Record<Category, string> = {
  authentication: "Authentication",
  access_control: "Access control",
  injection: "Injection",
  info_disclosure: "Information disclosure",
};

export interface Target {
  id: number;
  name: string;
  base_url: string;
  authorization_notes: string;
  in_scope: string[];
  out_of_scope: string[];
  test_email: string;
  has_test_password: boolean;
  owner_name: string;
  owner_email: string;
  created_at: string;
  scan_count: number;
  finding_count: number;
}

export interface Scan {
  id: number;
  target_id: number;
  target_name: string;
  status: "queued" | "running" | "completed" | "failed";
  phase: string;
  progress: number;
  categories: Category[];
  active_scan: boolean;
  ajax_spider: boolean;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  finding_count: number;
  endpoint_count: number;
}

export interface ScanDetail extends Scan {
  log: string;
  error: string;
  endpoints: { id: number; method: string; url: string; status_code: number | null; source: string }[];
}

export interface FindingSummary {
  id: number;
  scan_id: number;
  target_id: number;
  source: "zap" | "curl";
  title: string;
  category: Category;
  owasp: string;
  cwe_id: number | null;
  method: string;
  url: string;
  param: string;
  tool_severity: Severity;
  ai_status: "pending" | "running" | "done" | "failed";
  ai_severity: Severity | "";
  ai_cvss_score: number | null;
  status: ReviewStatus;
  final_severity: Severity | "";
  effective_severity: Severity;
  occurrences: number;
  created_at: string;
}

export interface Remediation {
  root_cause?: string;
  steps?: string[];
  code_language?: string;
  code_example?: string;
  verification?: string;
  references?: string[];
  error?: string;
}

export interface FindingDetail extends FindingSummary {
  tool_rule_id: string;
  description: string;
  wstg: string;
  attack: string;
  evidence: string;
  request_raw: string;
  response_raw: string;
  tool_confidence: string;
  ai_model: string;
  ai_summary: string;
  ai_impact: string;
  ai_rationale: string;
  ai_false_positive_hint: string;
  ai_cvss_vector: string;
  ai_error: string;
  ai_payload: Record<string, unknown> | null;
  ai_redactions: Record<string, number> | null;
  remediation_status: "none" | "running" | "done" | "failed";
  remediation: Remediation | null;
  remediation_model: string;
  reviewer: string;
  review_note: string;
  reviewed_at: string | null;
  affected_urls: string[];
  curl_command: string;
}

export interface Dashboard {
  targets: number;
  scans: number;
  scans_running: number;
  findings: number;
  pending: number;
  confirmed: number;
  rejected: number;
  ai_done: number;
  severity_confirmed: Record<Severity, number>;
  severity_open: Record<Severity, number>;
  by_category: Record<Category, Record<ReviewStatus, number>>;
  recent_scans: Scan[];
  redactions: Record<string, number>;
  ai_mode: string;
}

export interface Report {
  id: number;
  target_id: number;
  filename: string;
  findings_count: number;
  prepared_by: string;
  created_at: string;
}

export type NotifyEvent = "finding.detected" | "scan.analysed" | "scan.failed" | "finding.confirmed" | "report.generated";
export type ChannelKind = "email" | "discord" | "slack" | "telegram" | "webhook";

export const EVENTS: { key: NotifyEvent; label: string; hint: string }[] = [
  { key: "finding.detected", label: "Serious finding detected", hint: "Analysis rated a new finding at or above the threshold" },
  { key: "scan.analysed", label: "Scan analysed", hint: "Summary when every finding of a scan has been analysed" },
  { key: "scan.failed", label: "Scan failed", hint: "A scan stopped before finishing" },
  { key: "finding.confirmed", label: "Finding confirmed", hint: "An assessor verified a vulnerability" },
  { key: "report.generated", label: "Report generated", hint: "A PDF report is ready" },
];

export const CHANNEL_LABEL: Record<ChannelKind, string> = {
  email: "Email",
  discord: "Discord",
  slack: "Slack",
  telegram: "Telegram",
  webhook: "Webhook",
};

export interface Channel {
  id: number;
  name: string;
  kind: ChannelKind;
  config: Record<string, string | string[]>;
  events: NotifyEvent[];
  min_severity: Severity;
  target_id: number | null;
  notify_owner: boolean;
  enabled: boolean;
  last_status: "" | "sent" | "failed";
  last_error: string;
  last_sent_at: string | null;
  created_at: string;
}

export type ChannelInput = Pick<Channel, "name" | "kind" | "events" | "min_severity" | "target_id" | "notify_owner" | "enabled"> & {
  config: Record<string, string | string[]>;
};

export interface Delivery {
  channel_name: string;
  kind: ChannelKind;
  status: "queued" | "sent" | "failed";
  error: string;
}

export interface Notice {
  id: number;
  event: NotifyEvent | "test";
  severity: Severity | "";
  title: string;
  body: string;
  link: string;
  target_id: number | null;
  scan_id: number | null;
  finding_id: number | null;
  read: boolean;
  created_at: string;
  deliveries: Delivery[];
}

export interface Health {
  status: string;
  zap: string;
  curl: boolean;
  ai_mode: string;
  ai_model: string;
  allowed_hosts: string[];
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`/api${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
  });
  if (!res.ok) {
    let message = `${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      if (typeof body.detail === "string") message = body.detail;
      else if (Array.isArray(body.detail))
        message = body.detail.map((d: { msg: string; loc: string[] }) => `${d.loc.at(-1)}: ${d.msg}`).join("; ");
    } catch {
      /* not JSON */
    }
    throw new ApiError(res.status, message);
  }
  return res.status === 204 ? (undefined as T) : res.json();
}

const post = <T>(path: string, body?: unknown) =>
  request<T>(path, { method: "POST", body: body === undefined ? undefined : JSON.stringify(body) });

function qs(params: Record<string, string | number | undefined | null>) {
  const p = Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== "");
  return p.length ? "?" + new URLSearchParams(p.map(([k, v]) => [k, String(v)])).toString() : "";
}

export const api = {
  health: () => request<Health>("/health"),
  dashboard: (target_id?: number) => request<Dashboard>(`/dashboard${qs({ target_id })}`),
  targets: () => request<Target[]>("/targets"),
  target: (id: number) => request<Target>(`/targets/${id}`),
  createTarget: (body: Omit<Target, "id" | "created_at" | "scan_count" | "finding_count" | "has_test_password"> & { test_password: string }) =>
    post<Target>("/targets", body),
  updateTarget: (id: number, body: Partial<Target> & { test_password?: string }) =>
    request<Target>(`/targets/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  deleteTarget: (id: number) => request<void>(`/targets/${id}`, { method: "DELETE" }),
  scopeCheck: (id: number, url: string) => post<{ allowed: boolean; reason: string }>(`/targets/${id}/scope-check`, { url }),
  startScan: (id: number, body: { categories: Category[]; active_scan: boolean; ajax_spider: boolean }) =>
    post<Scan>(`/targets/${id}/scans`, body),
  scans: (target_id?: number) => request<Scan[]>(`/scans${qs({ target_id })}`),
  scan: (id: number) => request<ScanDetail>(`/scans/${id}`),
  analyzePending: (scanId: number) => post<{ queued: number }>(`/scans/${scanId}/analyze-pending`),
  findings: (f: { target_id?: number; scan_id?: number; status?: string; category?: string; severity?: string }) =>
    request<FindingSummary[]>(`/findings${qs(f)}`),
  finding: (id: number) => request<FindingDetail>(`/findings/${id}`),
  review: (id: number, body: { decision: "confirm" | "reject" | "reset"; severity?: Severity; reviewer?: string; note?: string }) =>
    post<FindingDetail>(`/findings/${id}/review`, body),
  reanalyze: (id: number) => post<FindingDetail>(`/findings/${id}/analyze`),
  remediate: (id: number) => post<FindingDetail>(`/findings/${id}/remediation`),
  reports: (target_id?: number) => request<Report[]>(`/reports${qs({ target_id })}`),
  createReport: (targetId: number, prepared_by: string) => post<Report>(`/targets/${targetId}/reports`, { prepared_by }),
  reportUrl: (id: number) => `/api/reports/${id}/download`,
  notifications: (opts: { unread?: boolean; limit?: number; finding_id?: number } = {}) =>
    request<Notice[]>(`/notifications${qs({ unread: opts.unread ? "true" : undefined, limit: opts.limit, finding_id: opts.finding_id })}`),
  notificationSummary: () => request<{ unread: number; latest_id: number; email_configured: boolean }>("/notifications/summary"),
  markRead: (body: { ids?: number[]; all?: boolean }) =>
    request<void>("/notifications/read", { method: "POST", body: JSON.stringify(body) }),
  channels: () => request<Channel[]>("/channels"),
  createChannel: (body: ChannelInput) => post<Channel>("/channels", body),
  updateChannel: (id: number, body: Partial<ChannelInput>) =>
    request<Channel>(`/channels/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  deleteChannel: (id: number) => request<void>(`/channels/${id}`, { method: "DELETE" }),
  testChannel: (id: number) => post<{ ok: boolean; error: string }>(`/channels/${id}/test`),
};

/** Notification links are absolute; turn same-origin ones into router paths. */
export function localPath(link: string): string | null {
  try {
    const u = new URL(link, window.location.origin);
    if (u.pathname.startsWith("/api/")) return null;
    return u.pathname + u.search;
  } catch {
    return null;
  }
}

export function ago(iso: string | null) {
  if (!iso) return "";
  const t = new Date(iso.endsWith("Z") || iso.includes("+") ? iso : iso + "Z").getTime();
  const s = Math.max(0, (Date.now() - t) / 1000);
  if (s < 45) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
}

export function fid(id: number) {
  return `BUNS-${String(id).padStart(3, "0")}`;
}

export function pathOf(url: string) {
  try {
    const u = new URL(url);
    return u.pathname + u.search + u.hash;
  } catch {
    return url;
  }
}

export function when(iso: string | null) {
  if (!iso) return "–";
  const d = new Date(iso.endsWith("Z") || iso.includes("+") ? iso : iso + "Z");
  return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

export function plural(n: number, one: string, many = one + "s") {
  return `${n} ${n === 1 ? one : many}`;
}

/** localStorage can be unavailable (private mode, sandboxed frames). */
export const store = {
  get(key: string) {
    try {
      return localStorage.getItem(key) ?? "";
    } catch {
      return "";
    }
  },
  set(key: string, value: string) {
    try {
      localStorage.setItem(key, value);
    } catch {
      /* ignore */
    }
  },
};
