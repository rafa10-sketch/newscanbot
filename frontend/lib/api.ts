/**
 * PentestBot Dashboard — API Client
 * Communicates with the FastAPI backend on port 8000.
 */

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
const API_TOKEN = process.env.NEXT_PUBLIC_API_TOKEN || "";

export interface ScanCreateResponse {
  scanId: string;
  state: string;
  target: string;
  scanMode: string;
  externalJobId: string | null;
}

export interface ScanStage {
  name: string;
  state: string;
  startedAt: string | null;
  completedAt: string | null;
  error: string | null;
}

export interface ScanSummary {
  subdomains?: number;
  open_ports?: number;
  live_hosts?: number;
  discovered_urls?: number;
  total_findings?: number;
  observed_findings?: number;
  excluded_findings?: number;
  risk_level?: string;
  duration?: string;
  tool_errors?: number;
}

export interface ScanStatus {
  scanId: string;
  target: string;
  state: string;
  scanMode: string;
  currentStage: string;
  progress: number;
  createdAt: string | null;
  startedAt: string | null;
  completedAt: string | null;
  error: string | null;
  pdfReady: boolean;
  reportFilename?: string | null;
  rawReady: boolean;
  rawFilename?: string | null;
  summary: ScanSummary | null;
  stages: ScanStage[];
}

export interface ScanListItem {
  scanId: string;
  target: string;
  state: string;
  scanMode: string;
  createdAt: string | null;
  completedAt: string | null;
  pdfReady: boolean;
  reportFilename?: string | null;
  rawReady: boolean;
  rawFilename?: string | null;
  summary: ScanSummary | null;
}

export interface LogEntry {
  id: string;
  createdAt: string | null;
  stage: string;
  message: string;
}

export interface ApiEvidenceObservation {
  name: string;
  method: string;
  url: string;
  authContext: string;
  status: number;
  expected: string;
  result: "pass" | "fail" | "finding" | "blocked";
  length: number;
  jsonFields: string[];
  blockedBy?: string | null;
}

export interface ApiEvidenceFinding {
  title: string;
  severity: string;
  description: string;
  affected: string[];
  kind: string;
  endpointName: string;
  jsonFields: string[];
  hasFinancialFields: boolean;
  confidence?: "confirmed" | "probable" | "needs_manual_validation" | "blocked" | "informational";
  confidenceScore?: number;
  confidenceReason?: string;
}

export interface ApiEvidenceValidationItem {
  title: string;
  kind: string;
  method: string;
  url: string;
  reason: string;
  status?: number | null;
}

export interface ApiEvidenceTestCase {
  name: string;
  method: string;
  url: string;
  expected: string;
  result: "pass" | "fail" | "finding" | "blocked";
  statuses: number[];
  jsonFields: string[];
  contexts: Array<{
    authContext: string;
    status: number;
    result: "pass" | "fail" | "finding" | "blocked";
  }>;
  summary: string;
}

export interface ApiEvidence {
  scanId: string;
  ready: boolean;
  verdict?: "pass" | "needs_review" | "finding" | "blocked";
  headline?: string;
  counts: {
    total: number;
    pass: number;
    fail: number;
    finding: number;
    blocked: number;
  };
  caseCounts?: {
    total: number;
    pass: number;
    fail: number;
    finding: number;
    blocked: number;
  };
  testCases?: ApiEvidenceTestCase[];
  observations: ApiEvidenceObservation[];
  findings: ApiEvidenceFinding[];
  validationQueue: ApiEvidenceValidationItem[];
}

export interface CreateScanOptions {
  originIp?: string;
  apiEndpoints?: string;
  customHeaders?: string;
  customCookies?: string;
}

async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const url = `${API_BASE}${path}`;
  
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options?.headers as Record<string, string>),
  };
  if (API_TOKEN) {
    headers["Authorization"] = `Bearer ${API_TOKEN}`;
  }

  const res = await fetch(url, {
    ...options,
    headers,
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(body.detail || body.message || `API error ${res.status}`);
  }
  return res.json();
}

export async function createScan(
  target: string,
  scanMode: string = "fast",
  options: CreateScanOptions = {}
): Promise<ScanCreateResponse> {
  return apiFetch<ScanCreateResponse>("/api/scans", {
    method: "POST",
    body: JSON.stringify({
      target,
      scanMode,
      originIp: options.originIp,
      apiEndpoints: options.apiEndpoints,
      customHeaders: options.customHeaders,
      customCookies: options.customCookies,
    }),
  });
}

export async function getScanStatus(scanId: string): Promise<ScanStatus> {
  return apiFetch<ScanStatus>(`/api/scans/${scanId}`);
}

export async function cancelScan(scanId: string): Promise<{ scanId: string; cancelled: boolean }> {
  return apiFetch(`/api/scans/${scanId}/cancel`, {
    method: "POST",
  });
}

export async function getScanLogs(
  scanId: string,
  after: number = 0
): Promise<{ entries: LogEntry[]; nextCursor: number }> {
  return apiFetch(`/api/scans/${scanId}/logs?after=${after}`);
}

export async function getApiEvidence(scanId: string): Promise<ApiEvidence> {
  return apiFetch<ApiEvidence>(`/api/scans/${scanId}/api-evidence`);
}

export async function listScans(): Promise<{ scans: ScanListItem[] }> {
  return apiFetch("/api/scans?limit=20");
}

export async function deleteScan(scanId: string): Promise<{ scanId: string; deleted: boolean }> {
  return apiFetch(`/api/scans/${scanId}`, {
    method: "DELETE",
  });
}

export async function downloadReport(scanId: string): Promise<void> {
  // Ambil data status terbaru untuk mendapatkan nama file asli
  const status = await getScanStatus(scanId);
  const reportFilename = status.reportFilename || `security_assessment_${scanId}.pdf`;

  const url = `${API_BASE}/api/scans/${scanId}/report`;
  const headers: Record<string, string> = {};
  if (API_TOKEN) {
    headers["Authorization"] = `Bearer ${API_TOKEN}`;
  }
  const res = await fetch(url, { headers });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(body.detail || `Failed to download report: ${res.status}`);
  }

  const blob = await res.blob();
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = reportFilename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(a.href);
}

export async function downloadRawData(scanId: string): Promise<void> {
  const status = await getScanStatus(scanId);
  const rawFilename = status.rawFilename || `raw_scan_data_${scanId}.json`;

  const url = `${API_BASE}/api/scans/${scanId}/raw`;
  const headers: Record<string, string> = {};
  if (API_TOKEN) {
    headers["Authorization"] = `Bearer ${API_TOKEN}`;
  }
  const res = await fetch(url, { headers });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(body.detail || `Failed to download raw data: ${res.status}`);
  }

  const blob = await res.blob();
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = rawFilename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(a.href);
}

export async function downloadApiEvidence(scanId: string): Promise<void> {
  const evidence = await getApiEvidence(scanId);
  const blob = new Blob([JSON.stringify(evidence, null, 2)], {
    type: "application/json",
  });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `api_evidence_summary_${scanId}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(a.href);
}

