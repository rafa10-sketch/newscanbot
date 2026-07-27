"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import { useParams } from "next/navigation";
import {
  getScanStatus,
  getScanLogs,
  getApiEvidence,
  downloadReport,
  downloadRawData,
  downloadApiEvidence,
  cancelScan,
  deleteScan,
  type ScanStatus,
  type LogEntry,
  type ApiEvidence,
} from "@/lib/api";

const STAGE_LABELS: Record<string, string> = {
  Queued: "Queued",
  Recon: "Subdomain Discovery",
  Resolver: "DNS Resolution",
  OriginIP: "Origin IP Detection",
  PortScan: "Port Scanning",
  ServiceScan: "Service Detection",
  HTTPProbe: "HTTP Probing",
  Fingerprint: "Fingerprinting",
  WebDiscovery: "Web Discovery",
  VulnScan: "Vulnerability Scan",
  TLSScan: "TLS Analysis",
  Aggregation: "Aggregation",
  AIAnalysis: "AI Analysis",
  Report: "Report Generation",
  Done: "Finished",
};

function stageIcon(state: string): string {
  switch (state) {
    case "completed":
      return "✓";
    case "running":
      return "⟳";
    case "failed":
      return "✗";
    default:
      return "○";
  }
}

function riskColor(level: string | undefined): string {
  switch (level?.toLowerCase()) {
    case "critical":
      return "var(--accent-red)";
    case "high":
      return "var(--accent-amber)";
    case "medium":
      return "var(--accent-amber)";
    case "low":
      return "var(--accent-cyan)";
    default:
      return "var(--text-muted)";
  }
}

function apiResultLabel(result: string): string {
  switch (result) {
    case "pass":
      return "PASS";
    case "finding":
      return "FINDING";
    case "blocked":
      return "BLOCKED";
    case "fail":
      return "FAIL";
    default:
      return result.toUpperCase();
  }
}

function confidenceLabel(confidence: string | undefined): string {
  switch (confidence) {
    case "confirmed":
      return "CONFIRMED";
    case "probable":
      return "PROBABLE";
    case "blocked":
      return "BLOCKED";
    case "informational":
      return "INFO";
    case "needs_manual_validation":
    default:
      return "MANUAL";
  }
}

export default function ScanPage() {
  const params = useParams();
  const scanId = params.id as string;

  const [scan, setScan] = useState<ScanStatus | null>(null);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [apiEvidence, setApiEvidence] = useState<ApiEvidence | null>(null);
  const [logCursor, setLogCursor] = useState(0);
  const [error, setError] = useState("");
  const [showTimeline, setShowTimeline] = useState(false);

  const logEndRef = useRef<HTMLDivElement>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const isTerminal = scan?.state === "completed" || scan?.state === "failed" || scan?.state === "cancelled";

  const handleCancel = async () => {
    if (!confirm("Are you sure you want to stop this scan?")) return;
    try {
      await cancelScan(scanId);
      await fetchStatus();
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to cancel scan");
    }
  };

  const handleDelete = async () => {
    if (!confirm("Are you sure you want to delete this scan history? This will remove all data and reports.")) return;
    try {
      await deleteScan(scanId);
      window.location.href = "/";
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to delete scan");
    }
  };

  const fetchStatus = useCallback(async () => {
    try {
      const status = await getScanStatus(scanId);
      setScan(status);
      return status;
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load scan");
      return null;
    }
  }, [scanId]);

  const fetchLogs = useCallback(async () => {
    try {
      const data = await getScanLogs(scanId, logCursor);
      if (data.entries.length > 0) {
        setLogs((prev) => [...prev, ...data.entries]);
        setLogCursor(data.nextCursor);
      }
    } catch {
      // Logs may not be available yet
    }
  }, [scanId, logCursor]);

  const fetchApiEvidence = useCallback(async () => {
    try {
      const evidence = await getApiEvidence(scanId);
      setApiEvidence(evidence);
    } catch {
      setApiEvidence(null);
    }
  }, [scanId]);

  // Initial load
  useEffect(() => {
    fetchStatus();
    fetchLogs();
  }, []);

  useEffect(() => {
    if (scan?.scanMode === "api" && (scan.rawReady || isTerminal)) {
      fetchApiEvidence();
    }
  }, [scan?.scanMode, scan?.rawReady, isTerminal, fetchApiEvidence]);

  // Polling
  useEffect(() => {
    if (isTerminal) {
      if (pollRef.current) clearInterval(pollRef.current);
      const finalRefresh = setTimeout(() => {
        fetchStatus();
        fetchLogs();
        if (scan?.scanMode === "api") {
          fetchApiEvidence();
        }
      }, 1000);
      return () => clearTimeout(finalRefresh);
    }

    pollRef.current = setInterval(async () => {
      const status = await fetchStatus();
      await fetchLogs();

      if (
        status &&
        (status.state === "completed" ||
          status.state === "failed" ||
          status.state === "cancelled")
      ) {
        if (pollRef.current) clearInterval(pollRef.current);
      }
    }, 3000);

    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [isTerminal, scan?.scanMode, fetchStatus, fetchLogs, fetchApiEvidence]);

  // Auto-scroll logs
  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  if (error && !scan) {
    return (
      <div className="scan-page">
        <div className="card">
          <div className="error-msg">{error}</div>
          <div className="actions-row" style={{ marginTop: "1rem" }}>
            <a href="/" className="btn btn-ghost">← Back to Home</a>
          </div>
        </div>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="scan-page">
        <div className="card" style={{ textAlign: "center", padding: "3rem" }}>
          <div style={{ fontSize: "1.5rem", marginBottom: "0.5rem" }}>⟳</div>
          <div style={{ color: "var(--text-secondary)" }}>Loading scan details…</div>
        </div>
      </div>
    );
  }

  const progressClass = scan.state === "completed"
    ? "completed"
    : scan.state === "failed"
      ? "failed"
      : "";
  const apiCaseCounts = apiEvidence?.caseCounts || apiEvidence?.counts || {
    total: 0,
    pass: 0,
    fail: 0,
    finding: 0,
    blocked: 0,
  };
  const apiTestCases = apiEvidence?.testCases || [];

  return (
    <div className="scan-page">
      {/* Target & Status */}
      <div className="card">
        <div className="target-badge">🎯 {scan.target}</div>
        {scan.scanMode && (
          <span className={`scan-mode-badge ${scan.scanMode}`}>
            {scan.scanMode === "deep"
              ? "🔬 In-Depth Scan"
              : scan.scanMode === "safe"
                ? "🛡️ Safe Scan"
                : scan.scanMode === "api"
                  ? "API Scan"
                  : "⚡ Fast Scan"}
          </span>
        )}

        {/* Parallel Execution Indicator - Premium Style */}
        {scan.stages.filter(s => s.state === 'running').length > 1 && (
          <div className="parallel-indicator glow-text-cyan">
            <span className="dot" />
            CONCURRENT PIPELINES ACTIVE
            <div className="worker-thread" style={{ marginLeft: '10px' }}>
              <span className="worker-dot" />
              Multi-Threaded Mode
            </div>
          </div>
        )}

        {/* Premium Concurrency Map */}
        <div className="pipeline-flow-container glow-card-active">
          {!isTerminal && <div className="scan-pulse" />}
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '1.5rem', textAlign: 'center', letterSpacing: '0.2em', fontWeight: 700 }}>
            LIVE CONCURRENCY MAP
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-around', alignItems: 'center', position: 'relative' }}>
            <div className="pipeline-node">
              <div className={`stage-icon ${scan.stages.some(s => s.state === 'running' && ["PortScan", "ServiceScan"].includes(s.name)) ? 'running' : ''}`}
                style={{ background: 'var(--bg-glass)', padding: '15px', borderRadius: '12px', fontSize: '1.5rem', border: '1px solid var(--border-color)' }}>🛡️</div>
              <div style={{ fontSize: '0.75rem', fontWeight: 600, marginTop: '0.5rem' }}>INFRASTRUCTURE</div>
              {scan.stages.some(s => s.state === 'running' && ["PortScan", "ServiceScan"].includes(s.name)) && (
                <div className="worker-thread"><span className="worker-dot" /> Scanning</div>
              )}
            </div>

            <div style={{ flex: 1, height: '1px', background: 'var(--border-color)', margin: '0 1rem', position: 'relative' }}>
              <div style={{ position: 'absolute', top: '-10px', left: '50%', transform: 'translateX(-50%)', background: 'var(--bg-card)', padding: '0 10px', fontSize: '0.6rem', color: 'var(--text-muted)' }}>PARALLEL BUS</div>
            </div>

            <div className="pipeline-node">
              <div className={`stage-icon ${scan.stages.some(s => s.state === 'running' && ["HTTPProbe", "Fingerprint", "WebDiscovery", "VulnScan", "TLSScan"].includes(s.name)) ? 'running' : ''}`}
                style={{ background: 'var(--bg-glass)', padding: '15px', borderRadius: '12px', fontSize: '1.5rem', border: '1px solid var(--border-color)' }}>🌐</div>
              <div style={{ fontSize: '0.75rem', fontWeight: 600, marginTop: '0.5rem' }}>WEB ANALYSIS</div>
              {scan.stages.some(s => s.state === 'running' && ["HTTPProbe", "Fingerprint", "WebDiscovery", "VulnScan", "TLSScan"].includes(s.name)) && (
                <div className="worker-thread"><span className="worker-dot" /> Analyzing</div>
              )}
            </div>
          </div>
        </div>

        {/* Progress Bar */}
        <div className="progress-section" style={{ marginTop: "2rem" }}>
          <div className="progress-header">
            <span className="progress-label">
              {isTerminal
                ? scan.state === "completed"
                  ? "Scan Complete"
                  : "Scan Failed"
                : STAGE_LABELS[scan.currentStage] || scan.currentStage}
            </span>
            <span className="progress-value">{scan.progress}%</span>
          </div>
          <div className="progress-bar-track">
            <div
              className={`progress-bar-fill ${progressClass}`}
              style={{ width: `${scan.progress}%` }}
            />
          </div>
        </div>

        {/* Pipeline Stages (Parallel View) */}
        <div className="stages-grid" style={{ marginTop: "1.5rem" }}>

          <div className="stages-column">
            <div className="column-title">Infrastructure & Foundation</div>
            <div className="stages-list">
              {scan.stages
                .filter((s) => ["Queued", "Recon", "Resolver", "OriginIP", "PortScan", "ServiceScan"].includes(s.name))
                .map((stage) => (
                  <div key={stage.name} className={`stage-item ${stage.state}`}>
                    <span className={`stage-icon ${stage.state}`}>{stageIcon(stage.state)}</span>
                    <span className="stage-name">{STAGE_LABELS[stage.name] || stage.name}</span>
                    {(() => {
                      if (!stage.completedAt || !stage.startedAt) return null;
                      const durationValue = ((new Date(stage.completedAt).getTime() - new Date(stage.startedAt).getTime()) / 1000).toFixed(1);
                      const SKIPPABLE_STAGES = ["ServiceScan", "VulnScan", "PortScan", "WebDiscovery", "Fingerprint", "Recon"];
                      const isErrorSkip = stage.error && stage.error.toLowerCase().includes("skip");
                      const isZeroSkip = durationValue === "0.0" && SKIPPABLE_STAGES.includes(stage.name);
                      const isSkipped = isErrorSkip || isZeroSkip;
                      const tooltipText = stage.error || (isSkipped ? "Stage was automatically skipped by pipeline rules due to CDN detection" : undefined);
                      return (
                        <span className="stage-time" title={tooltipText} style={isSkipped ? { fontStyle: "italic", color: "var(--text-muted)" } : {}}>
                          {isSkipped ? "Skipped" : `${durationValue}s`}
                        </span>
                      );
                    })()}
                  </div>
                ))}
            </div>
          </div>

          <div className="stages-column">
            <div className="column-title">Web & App Analysis</div>
            <div className="stages-list">
              {scan.stages
                .filter((s) => !["Queued", "Recon", "Resolver", "OriginIP", "PortScan", "ServiceScan"].includes(s.name))
                .map((stage) => (
                  <div key={stage.name} className={`stage-item ${stage.state}`}>
                    <span className={`stage-icon ${stage.state}`}>{stageIcon(stage.state)}</span>
                    <span className="stage-name">{STAGE_LABELS[stage.name] || stage.name}</span>
                    {(() => {
                      if (!stage.completedAt || !stage.startedAt) return null;
                      const durationValue = ((new Date(stage.completedAt).getTime() - new Date(stage.startedAt).getTime()) / 1000).toFixed(1);
                      const SKIPPABLE_STAGES = ["ServiceScan", "VulnScan", "PortScan", "WebDiscovery", "Fingerprint", "Recon"];
                      const isErrorSkip = stage.error && stage.error.toLowerCase().includes("skip");
                      const isZeroSkip = durationValue === "0.0" && SKIPPABLE_STAGES.includes(stage.name);
                      const isSkipped = isErrorSkip || isZeroSkip;
                      const tooltipText = stage.error || (isSkipped ? "Stage was automatically skipped by pipeline rules due to CDN detection" : undefined);
                      return (
                        <span className="stage-time" title={tooltipText} style={isSkipped ? { fontStyle: "italic", color: "var(--text-muted)" } : {}}>
                          {isSkipped ? "Skipped" : `${durationValue}s`}
                        </span>
                      );
                    })()}
                  </div>
                ))}
            </div>
          </div>
        </div>

        {/* Post-Scan Timeline Proof */}
        {isTerminal && (
          <div className="timeline-container" style={{ marginTop: '2rem' }}>
            <div className="timeline-header">
              <div className="card-title" style={{ margin: 0 }}>📊 Execution Timeline Analysis</div>
              <div className="card-subtitle">Historical proof of parallel task synchronization</div>
            </div>
            <div className="timeline-chart">
              {(() => {
                const stagesWithTime = scan.stages.filter(s => s.startedAt);
                const minStart = Math.min(...stagesWithTime.map(s => new Date(s.startedAt!).getTime()));
                const maxEnd = Math.max(...stagesWithTime.map(s => s.completedAt ? new Date(s.completedAt).getTime() : Date.now()));
                const totalDuration = maxEnd - minStart || 1;

                return (
                  <>
                    {scan.stages.map(stage => {
                      if (!stage.startedAt) return null;
                      const start = new Date(stage.startedAt).getTime();
                      const end = stage.completedAt ? new Date(stage.completedAt).getTime() : Date.now();
                      const left = ((start - minStart) / totalDuration) * 100;
                      const width = ((end - start) / totalDuration) * 100;

                      return (
                        <div key={stage.name} className="timeline-row">
                          <div className="timeline-label">{STAGE_LABELS[stage.name] || stage.name}</div>
                          <div className="timeline-track">
                            <div className={`timeline-bar ${stage.state}`} style={{ left: `${left}%`, width: `${Math.max(width, 1)}%` }} />
                          </div>
                        </div>
                      );
                    })}
                    <div className="timeline-axis">
                      <span className="timeline-tick">0s</span>
                      <span className="timeline-tick">{(totalDuration / 1000).toFixed(1)}s</span>
                    </div>
                  </>
                );
              })()}
            </div>
          </div>
        )}

      </div>

      {/* Summary (when completed) */}
      {scan.state === "completed" && scan.summary && (
        <div className="card">
          <div className="card-header">
            <div className="card-title">Scan Summary</div>
            <div className="card-subtitle">
              Assessment completed in {scan.summary.duration || "—"}
            </div>
          </div>
          <div className="risk-level-row">
            <div
              className="risk-level-value"
              style={{ color: riskColor(scan.summary.risk_level) }}
            >
              {scan.summary.risk_level || "—"}
            </div>
            <div className="risk-level-label">Risk Level</div>
          </div>
          <div className="stats-grid">
            <div className="stat-card">
              <div className="stat-value">
                {scan.summary.total_findings ?? 0}
              </div>
              <div className="stat-label">Findings</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">
                {scan.summary.subdomains ?? 0}
              </div>
              <div className="stat-label">Subdomains</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">
                {scan.summary.open_ports ?? 0}
              </div>
              <div className="stat-label">Open Ports</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">
                {scan.summary.live_hosts ?? 0}
              </div>
              <div className="stat-label">Live Hosts</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">
                {scan.summary.discovered_urls ?? 0}
              </div>
              <div className="stat-label">URLs</div>
            </div>
          </div>
        </div>
      )}

      {scan.scanMode === "api" && apiEvidence?.ready && (
        <div className="card">
          <div className="card-header">
            <div className="card-title">API Evidence Summary</div>
            <div className="card-subtitle">
              Deterministic API matrix results. Secrets and sensitive query values are redacted.
            </div>
          </div>

          {apiEvidence.headline && (
            <div className={`api-verdict-card ${apiEvidence.verdict || "pass"}`}>
              <span>{apiResultLabel(apiEvidence.verdict === "needs_review" ? "fail" : apiEvidence.verdict || "pass")}</span>
              <strong>{apiEvidence.headline}</strong>
            </div>
          )}

          <div className="api-evidence-stats">
            <div className="api-evidence-stat">
              <span>Test Cases</span>
              <strong>{apiCaseCounts.total}</strong>
            </div>
            <div className="api-evidence-stat pass">
              <span>Pass</span>
              <strong>{apiCaseCounts.pass}</strong>
            </div>
            <div className="api-evidence-stat finding">
              <span>Findings</span>
              <strong>{apiCaseCounts.finding}</strong>
            </div>
            <div className="api-evidence-stat fail">
              <span>Fail</span>
              <strong>{apiCaseCounts.fail}</strong>
            </div>
            <div className="api-evidence-stat blocked">
              <span>Blocked</span>
              <strong>{apiCaseCounts.blocked}</strong>
            </div>
          </div>

          {apiTestCases.length > 0 && (
            <div className="api-review-list">
              {apiTestCases.map((testCase, index) => (
                <div className={`api-review-card ${testCase.result}`} key={`${testCase.name}-${index}`}>
                  <div className="api-review-topline">
                    <span className={`api-result-pill ${testCase.result}`}>
                      {apiResultLabel(testCase.result)}
                    </span>
                    <div>
                      <strong>{testCase.name}</strong>
                      <div className="api-test-url">{testCase.method} {testCase.url}</div>
                    </div>
                  </div>
                  <p>{testCase.summary}</p>
                  <div className="api-context-list">
                    {testCase.contexts.map((context, contextIndex) => (
                      <span key={`${context.authContext}-${contextIndex}`}>
                        {context.authContext}: HTTP {context.status}
                      </span>
                    ))}
                  </div>
                  {testCase.jsonFields.length > 0 && (
                    <div className="api-fields">Fields: {testCase.jsonFields.join(", ")}</div>
                  )}
                </div>
              ))}
            </div>
          )}

          {apiEvidence.findings.length > 0 && (
            <div className="api-finding-list">
              {apiEvidence.findings.map((finding, index) => (
                <div className="api-finding-card" key={`${finding.title}-${index}`}>
                  <div>
                    <span className={`api-severity ${finding.severity.toLowerCase()}`}>{finding.severity}</span>
                    <span className={`api-confidence ${finding.confidence || "needs_manual_validation"}`}>
                      {confidenceLabel(finding.confidence)}
                      {typeof finding.confidenceScore === "number" ? ` ${finding.confidenceScore}` : ""}
                    </span>
                    <strong>{finding.title}</strong>
                  </div>
                  <p>{finding.description}</p>
                  {finding.confidenceReason && (
                    <div className="api-fields">Confidence: {finding.confidenceReason}</div>
                  )}
                  {finding.jsonFields.length > 0 && (
                    <div className="api-fields">Fields: {finding.jsonFields.join(", ")}</div>
                  )}
                </div>
              ))}
            </div>
          )}

          <div className="api-raw-heading">Request detail</div>
          <div className="api-evidence-table-wrap">
            <table className="api-evidence-table">
              <thead>
                <tr>
                  <th>Test Case</th>
                  <th>Method</th>
                  <th>Status</th>
                  <th>Expected</th>
                  <th>Result</th>
                  <th>Fields</th>
                </tr>
              </thead>
              <tbody>
                {apiEvidence.observations.map((obs, index) => (
                  <tr key={`${obs.name}-${obs.authContext}-${index}`}>
                    <td>
                      <div className="api-test-name">{obs.name}</div>
                      <div className="api-test-url">{obs.url}</div>
                      <div className="api-test-context">{obs.authContext}</div>
                    </td>
                    <td>{obs.method}</td>
                    <td>{obs.status}</td>
                    <td>{obs.expected}</td>
                    <td>
                      <span className={`api-result-pill ${obs.result}`}>
                        {apiResultLabel(obs.result)}
                      </span>
                    </td>
                    <td>{obs.jsonFields.length ? obs.jsonFields.join(", ") : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {apiEvidence.counts.blocked > 0 && (
            <div className="api-evidence-note">
              Some requests were blocked before reaching the application, usually by a CDN/WAF challenge.
              Re-run from an allowlisted network or with an authorized origin IP to validate API behavior.
            </div>
          )}
        </div>
      )}

      {/* Error Detail */}
      {scan.state === "failed" && scan.error && (
        <div className="card">
          <div className="error-msg">{scan.error}</div>
        </div>
      )}

      {/* Actions */}
      <div className="actions-row">
        <a href="/" className="btn btn-ghost">
          ← New Scan
        </a>
        {!isTerminal && (
          <button
            className="btn"
            style={{ backgroundColor: "var(--accent-red)", color: "white" }}
            onClick={handleCancel}
          >
            🛑 Stop Scan
          </button>
        )}
        {isTerminal && (
          <button
            className="btn btn-ghost"
            style={{ color: "var(--accent-red)", borderColor: "rgba(239, 68, 68, 0.2)" }}
            onClick={handleDelete}
          >
            🗑️ Delete History
          </button>
        )}
        {scan.pdfReady && (
          <button
            className="btn btn-success"
            onClick={() => downloadReport(scanId).catch((e) => alert(e.message))}
          >
            📄 Download PDF Report
          </button>
        )}
        {scan.rawReady && (
          <button
            className="btn btn-ghost"
            style={{ color: "var(--accent-cyan)", borderColor: "rgba(34, 211, 238, 0.2)" }}
            onClick={() => (
              scan.scanMode === "api" ? downloadApiEvidence(scanId) : downloadRawData(scanId)
            ).catch((e) => alert(e.message))}
          >
            {scan.scanMode === "api" ? "📊 Download API Summary JSON" : "📊 Download Raw JSON"}
          </button>
        )}
      </div>

      {/* Live Logs */}
      {logs.length > 0 && (
        <div className="card">
          <div className="card-header">
            <div className="card-title">Scan Log</div>
            <div className="card-subtitle">
              {logs.length} entries · {isTerminal ? "Final" : "Live"}
            </div>
          </div>
          <div className="log-viewer">
            {logs.map((entry) => (
              <div key={entry.id} className="log-entry">
                <span className="log-stage">[{entry.stage}]</span>
                <span className="log-message">{entry.message}</span>
              </div>
            ))}
            <div ref={logEndRef} />
          </div>
        </div>
      )}
    </div>
  );
}
