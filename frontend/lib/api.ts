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

export async function createScan(target: string, scanMode: string = "fast"): Promise<ScanCreateResponse> {
  return apiFetch<ScanCreateResponse>("/api/scans", {
    method: "POST",
    body: JSON.stringify({ target, scanMode }),
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
