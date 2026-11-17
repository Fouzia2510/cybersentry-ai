"use client";

import { useEffect, useState } from "react";

type ScanFinding = { code: string; severity: string; title: string; description: string; recommendation: string; evidence?: string };
type ScanRecord = { id: string; domain: string; score: number; status: string; findings: ScanFinding[]; summary: Record<string, number>; http_status: number | null; tls_protocol: string | null; created_at: string };

const navigation = [
  { name: "Overview", icon: "◫" },
  { name: "Domain Management", icon: "◎" },
  { name: "Website Scanner", icon: "⌕" },
  { name: "Threat Intelligence", icon: "◈" },
  { name: "Vulnerabilities", icon: "⚠" },
  { name: "Security Reports", icon: "▤" },
];


export default function Home() {
  const [active, setActive] = useState("Overview");
  const [scanning, setScanning] = useState(false);
  const [scanMessage, setScanMessage] = useState("");
  const [selectedScanDomain, setSelectedScanDomain] = useState("");
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [scanResult, setScanResult] = useState<ScanRecord | null>(null);
  const [scanHistoryError, setScanHistoryError] = useState("");
  const [userEmail, setUserEmail] = useState<string | null>(null);
  const [domains, setDomains] = useState<Array<{ id: string; domain: string; verificationStatus: string; createdAt: string }>>([]);
  const [domainLoading, setDomainLoading] = useState(true);
  const [domainError, setDomainError] = useState("");
  const [domainInput, setDomainInput] = useState("");
  const [challenge, setChallenge] = useState<{
    domain: string;
    recordName: string;
    recordValue: string;
    expiresAt: string;
  } | null>(null);
  const [domainActionBusy, setDomainActionBusy] = useState(false);
  const [domainActionMessage, setDomainActionMessage] = useState("");
  const [refreshing, setRefreshing] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);
  const [refreshMessage, setRefreshMessage] = useState("");

  async function refreshScans() {
    setScanHistoryError("");
    try {
      const response = await fetch("/api/scans", { cache: "no-store" });
      const result = await response.json();
      if (!response.ok) {
        setScanHistoryError(result.error || "Could not load scan history.");
        return;
      }
      setScans(result.scans || []);
      if (result.scans?.[0]) setScanResult(result.scans[0]);
    } catch {
      setScanHistoryError("Could not reach the scan history service.");
    }
  }

  async function startSecurityScan() {
    if (!selectedScanDomain) {
      setScanMessage("Verify a domain in Domain Management before starting a security scan.");
      return;
    }
    setScanning(true);
    setScanMessage("Running passive HTTPS security checks...");
    try {
      const response = await fetch("/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: selectedScanDomain }),
      });
      const result = await response.json();
      if (!response.ok) {
        setScanMessage(result.error || "Security scan could not be completed.");
        return;
      }
      setScanResult(result.scan);
      setScanMessage("Security assessment completed and saved to your reports.");
      await refreshScans();
    } catch {
      setScanMessage("Could not reach the security scan service. Please try again.");
    } finally {
      setScanning(false);
    }
  }

  async function refreshDashboard() {
    if (refreshing) return;
    setRefreshing(true);
    setRefreshMessage("");
    try {
      const response = await fetch("/api/health", { cache: "no-store" });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || "Health check failed.");
      setLastUpdated(new Date().toLocaleTimeString());
      setRefreshMessage(
        result.supabase?.status === "reachable"
          ? "Workspace checked. Database API is reachable."
          : "Workspace checked. Database service is not configured or could not be reached."
      );
    } catch {
      setRefreshMessage("Unable to refresh right now. Check your connection and try again.");
    } finally {
      setRefreshing(false);
    }
  }

  async function refreshDomains() {
    setDomainLoading(true);
    setDomainError("");
    try {
      const response = await fetch("/api/domains", { cache: "no-store" });
      const result = await response.json();
      if (!response.ok) {
        setDomainError(result.error || "Could not load domains.");
        setDomains([]);
        return;
      }
      setDomains(result.domains || []);
      const verifiedDomain = (result.domains || []).find((domain: { verificationStatus: string }) => domain.verificationStatus === "verified");
      if (verifiedDomain) setSelectedScanDomain((current) => current || verifiedDomain.domain);
    } catch {
      setDomainError("Could not reach the domain service.");
    } finally {
      setDomainLoading(false);
    }
  }

  async function createDomainChallenge() {
    if (!userEmail) {
      setDomainActionMessage("Sign in first to connect a domain.");
      return;
    }
    setDomainActionBusy(true);
    setDomainActionMessage("");
    setChallenge(null);
    try {
      const response = await fetch("/api/domains", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: domainInput }),
      });
      const result = await response.json();
      if (!response.ok) {
        setDomainActionMessage(result.error || "Could not create a DNS challenge.");
        return;
      }
      setChallenge({
        domain: result.domain,
        recordName: result.recordName,
        recordValue: result.recordValue,
        expiresAt: result.expiresAt,
      });
      setDomainActionMessage("Add this TXT record to your domain's DNS, then select Verify ownership.");
      await refreshDomains();
    } catch {
      setDomainActionMessage("Could not reach the domain service. Please try again.");
    } finally {
      setDomainActionBusy(false);
    }
  }

  async function verifyDomainOwnership() {
    if (!challenge) return;
    setDomainActionBusy(true);
    setDomainActionMessage("");
    try {
      const response = await fetch("/api/domains/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: challenge.domain, token: challenge.recordValue }),
      });
      const result = await response.json();
      if (!response.ok) {
        setDomainActionMessage(result.error || "Domain verification failed.");
        return;
      }
      setDomainActionMessage("Domain ownership verified successfully.");
      setChallenge(null);
      setDomainInput("");
      await refreshDomains();
    } catch {
      setDomainActionMessage("Could not reach the verification service. Please try again.");
    } finally {
      setDomainActionBusy(false);
    }
  }

  useEffect(() => {
    let mounted = true;
    async function loadSession() {
      try {
        const response = await fetch("/api/auth/session", { cache: "no-store" });
        if (!response.ok) {
          if (mounted) {
            setUserEmail(null);
            setDomainLoading(false);
          }
          return;
        }
        const session = await response.json();
        if (mounted) setUserEmail(session.user?.email ?? null);
        if (mounted) {
          await refreshDomains();
          await refreshScans();
        }
      } catch {
        if (mounted) {
          setUserEmail(null);
          setDomainLoading(false);
        }
      }
    }
    void loadSession();
    return () => { mounted = false; };
  }, []);

  async function handleLogout() {
    try {
      await fetch("/api/auth/logout", { method: "POST" });
    } finally {
      setUserEmail(null);
      setDomains([]);
      setScans([]);
      setScanResult(null);
      setActive("Overview");
    }
  }


  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">C</div>
          <div>
            <h1>CyberSentry<span>AI</span></h1>
            <p>SECURITY INTELLIGENCE</p>
          </div>
        </div>

        <div className="workspace">
          <span className="workspace-dot" />
          PERSONAL WORKSPACE
        </div>

        <p className="nav-label">PLATFORM</p>

        <nav className="navigation">
          {navigation.map((item) => (
            <button
              key={item.name}
              onClick={() => setActive(item.name)}
              className={`nav-item ${active === item.name ? "active" : ""}`}
            >
              <span className="nav-icon">{item.icon}</span>
              {item.name}
              {item.name === "Vulnerabilities" && (
                <span className="nav-count">4</span>
              )}
            </button>
          ))}
        </nav>

        <p className="nav-label tools-label">SYSTEM</p>

        <button
          className={`nav-item ${active === "Settings" ? "active" : ""}`}
          onClick={() => setActive("Settings")}
        >
          <span className="nav-icon">⚙</span>
          Settings
        </button>

        <div className="sidebar-bottom">
          <div className="upgrade-card">
            <div className="upgrade-icon">✦</div>
            <h3>Security starts here.</h3>
            <p>Build a stronger security posture with CyberSentryAI.</p>
            <span>DEVELOPMENT EDITION</span>
          </div>

          <div className="profile">
            <div className="avatar">F</div>
            <div>
              <strong>Workspace Owner</strong>
              <small>Administrator</small>
            </div>
            <span className="profile-menu">•••</span>
          </div>
        </div>
      </aside>

      <section className="main-area">
        <header className="topbar">
          <div className="breadcrumb">
            <span>Workspace</span>
            <span>/</span>
            <strong>{active}</strong>
          </div>

          <div className="topbar-right">
            {userEmail ? (
              <button className="auth-nav-button" onClick={handleLogout}>Sign out</button>
            ) : (
              <a className="auth-nav-button" href="/login">Sign in</a>
            )}
            <span className="environment">
              <span className="status-dot" />
              DEVELOPMENT
            </span>
            <button
              className="notification-button"
              aria-label="Notifications"
              onClick={() => setActive("Security Reports")}
            >
              ♧
              <i />
            </button>
            <div className="top-avatar">{userEmail ? userEmail.charAt(0).toUpperCase() : "?"}</div>
          </div>
        </header>

        <div className="dashboard-content">
          <div className="welcome-row">
            <div>
              <div className="eyebrow">
                <span className="live-dot" />
                SECURITY OPERATIONS CENTER
              </div>
              <h2>
                {active === "Overview"
                  ? "Security overview"
                  : active}
              </h2>
              <p>
                Your cybersecurity workspace. Monitor, assess and improve
                your security posture.
              </p>
            </div>

            <div className="refresh-control">
              <button
                className="secondary-button"
                onClick={refreshDashboard}
                disabled={refreshing}
                aria-busy={refreshing}
              >
                <span className={refreshing ? "refresh-spinner" : ""}>↻</span>
                {refreshing ? "Checking services..." : "Refresh dashboard"}
              </button>
              <span className="refresh-meta">
                {lastUpdated ? `Last checked at ${lastUpdated}` : "Live service check"}
              </span>
              {refreshMessage && <span className="refresh-feedback" role="status">{refreshMessage}</span>}
            </div>
          </div>

          {active !== "Overview" && active !== "Domain Management" && active !== "Website Scanner" && active !== "Security Reports" && active !== "Vulnerabilities" && (
            <div className="section-notice">
              <strong>{active}</strong>
              <p>
                This module is part of the CyberSentryAI development roadmap.
                Its production functionality will be added in a future release.
              </p>
              <button onClick={() => setActive("Overview")}>
                Return to overview →
              </button>
            </div>
          )}

          {active === "Domain Management" && (
            <section className="content-panel domain-management">
              <div className="panel-title">
                <div>
                  <h3>Your domains</h3>
                  <p>Connect a domain and prove ownership with a DNS TXT record</p>
                </div>
                <button onClick={refreshDomains} disabled={domainLoading}>
                  {domainLoading ? "Loading..." : "↻ Refresh"}
                </button>
              </div>

              {!userEmail ? (
                <div className="domain-connect">
                  <p className="domain-empty">Sign in to connect and manage domains in your workspace.</p>
                  <a className="auth-nav-button" href="/login">Sign in / Create account</a>
                </div>
              ) : (
                <div className="domain-connect">
                  <label className="domain-input-label" htmlFor="domain-connect-input">Domain name</label>
                  <div className="domain-connect-form">
                    <input
                      id="domain-connect-input"
                      value={domainInput}
                      onChange={(event) => setDomainInput(event.target.value)}
                      onKeyDown={(event) => {
                        if (event.key === "Enter") void createDomainChallenge();
                      }}
                      placeholder="example.com"
                      autoComplete="url"
                    />
                    <button onClick={createDomainChallenge} disabled={domainActionBusy || !domainInput.trim()}>
                      {domainActionBusy ? "Please wait..." : "Connect domain"}
                    </button>
                  </div>
                </div>
              )}

              {domainActionMessage && <p className="domain-action-message" role="status">{domainActionMessage}</p>}
              {challenge && (
                <div className="dns-challenge">
                  <h4>DNS ownership challenge · {challenge.domain}</h4>
                  <p>Create this TXT record with your DNS provider:</p>
                  <dl>
                    <div><dt>Type</dt><dd>TXT</dd></div>
                    <div><dt>Name / Host</dt><dd>{challenge.recordName}</dd></div>
                    <div><dt>Value</dt><dd className="dns-value">{challenge.recordValue}</dd></div>
                    <div><dt>Expires</dt><dd>{new Date(challenge.expiresAt).toLocaleString()}</dd></div>
                  </dl>
                  <button onClick={verifyDomainOwnership} disabled={domainActionBusy}>
                    {domainActionBusy ? "Checking DNS..." : "Verify ownership"}
                  </button>
                </div>
              )}

              {domainError && <p className="domain-error" role="alert">{domainError}</p>}
              {domainLoading ? (
                <p className="domain-empty">Loading your domains...</p>
              ) : domains.length === 0 ? (
                <p className="domain-empty">No domains saved yet.</p>
              ) : (
                <div className="domain-list">
                  {domains.map((domain) => (
                    <div className="domain-row" key={domain.id}>
                      <div>
                        <strong>{domain.domain}</strong>
                        <small>Added {new Date(domain.createdAt).toLocaleDateString()}</small>
                      </div>
                      <span className={domain.verificationStatus === "verified" ? "domain-status verified" : "domain-status pending"}>
                        {domain.verificationStatus}
                      </span>
                    </div>
                  ))}
                </div>
              )}
              <p className="domain-note">DNS ownership verification only. This does not scan the website or test for vulnerabilities.</p>
            </section>
          )}

          <div className="stats-grid">
            <article className="stat-card">
              <div className="stat-top">
                <span>SECURITY SCORE</span>
                <span className="stat-icon blue">◈</span>
              </div>
              <div className="stat-value">{scans[0] ? scans[0].score : "--"}<small>/100</small></div>
              <div className="stat-footer">{scans[0] ? `Latest assessment · ${scans[0].domain}` : "Awaiting first verified scan"}</div>
            </article>

            <article className="stat-card">
              <div className="stat-top">
                <span>MONITORED WEBSITES</span>
                <span className="stat-icon cyan">◎</span>
              </div>
              <div className="stat-value">{domains.filter((domain) => domain.verificationStatus === "verified").length.toString().padStart(2, "0")}</div>
              <div className="stat-footer">Verified websites</div>
            </article>

            <article className="stat-card">
              <div className="stat-top">
                <span>VULNERABILITIES</span>
                <span className="stat-icon orange">⚠</span>
              </div>
              <div className="stat-value">{scans[0]?.findings?.length ?? "--"}</div>
              <div className="stat-footer">{scans[0] ? "Findings in latest scan" : "No completed scans yet"}</div>
            </article>

            <article className="stat-card">
              <div className="stat-top">
                <span>ACTIVE THREATS</span>
                <span className="stat-icon red">⌁</span>
              </div>
              <div className="stat-value">--</div>
              <div className="stat-footer">Threat monitoring not connected</div>
            </article>
          </div>

          {(active === "Overview" || active === "Website Scanner") && (
            <section className="scanner-panel">
              <div className="panel-heading">
                <div>
                  <div className="eyebrow">WEBSITE SECURITY</div>
                  <h3>Website security assessment</h3>
                  <p>Run passive HTTPS configuration checks on a domain whose ownership you have verified.</p>
                </div>
                <div className="scanner-symbol">⌕</div>
              </div>

              <div className="scan-form">
                <div className="url-input-wrap">
                  <span>◎</span>
                  <select
                    value={selectedScanDomain}
                    onChange={(event) => setSelectedScanDomain(event.target.value)}
                    aria-label="Verified domain to scan"
                    disabled={!domains.some((domain) => domain.verificationStatus === "verified")}
                  >
                    <option value="">Select a verified domain</option>
                    {domains.filter((domain) => domain.verificationStatus === "verified").map((domain) => (
                      <option key={domain.id} value={domain.domain}>{domain.domain}</option>
                    ))}
                  </select>
                </div>
                <button
                  className="scan-button"
                  onClick={startSecurityScan}
                  disabled={scanning || !selectedScanDomain}
                >
                  {scanning ? "Assessing website..." : "Run security assessment →"}
                </button>
              </div>

              {scanMessage && <div className="scan-message" role="status">{scanMessage}</div>}
              {!domains.some((domain) => domain.verificationStatus === "verified") && (
                <div className="scan-disclaimer">
                  <span>ⓘ</span>
                  Verify ownership of your domain in Domain Management to enable scanning.
                  <button type="button" onClick={() => setActive("Domain Management")}>Manage domains →</button>
                </div>
              )}
              <div className="scan-disclaimer">
                <span>ⓘ</span>
                Passive HTTPS checks only: security headers, TLS protocol and certificate expiry. No exploitation, password testing, crawling or intrusive requests.
              </div>

              {scanResult && (
                <div className="scan-result">
                  <div className="scan-result-heading">
                    <div>
                      <span className="eyebrow">LATEST ASSESSMENT</span>
                      <h4>{scanResult.domain}</h4>
                      <p>Checked {new Date(scanResult.created_at).toLocaleString()} · HTTP {scanResult.http_status ?? "—"} · {scanResult.tls_protocol ?? "TLS details unavailable"}</p>
                    </div>
                    <div className="scan-score"><strong>{scanResult.score}</strong><span>/100</span></div>
                  </div>
                  <div className="finding-summary">
                    {(["critical", "high", "medium", "low", "info"] as const).map((severity) => (
                      <span key={severity} className={`finding-count ${severity}`}>
                        {scanResult.summary?.[severity] ?? 0} {severity}
                      </span>
                    ))}
                  </div>
                  {scanResult.findings?.length ? (
                    <div className="finding-list">
                      {scanResult.findings.map((finding) => (
                        <article className="finding-card" key={finding.code}>
                          <div><span className={`severity ${finding.severity}`}>{finding.severity}</span><strong>{finding.title}</strong></div>
                          <p>{finding.description}</p>
                          <small>Recommended action: {finding.recommendation}</small>
                        </article>
                      ))}
                    </div>
                  ) : (
                    <p className="domain-empty">No findings were detected by the checks performed. This is not a guarantee that the website is vulnerability-free.</p>
                  )}
                </div>
              )}
            </section>
          )}

          {active === "Security Reports" && (
            <section className="content-panel report-panel">
              <div className="panel-title"><div><h3>Security assessment reports</h3><p>Saved reports from your verified domains</p></div><button onClick={refreshScans}>↻ Refresh</button></div>
              {scanHistoryError && <p className="domain-error" role="alert">{scanHistoryError}</p>}
              {scans.length === 0 ? <p className="domain-empty">No saved reports yet. Run a security assessment on a verified domain to create your first report.</p> : (
                <div className="report-list">{scans.map((scan) => (
                  <button className="report-row" key={scan.id} onClick={() => { setScanResult(scan); setSelectedScanDomain(scan.domain); setActive("Website Scanner"); }}>
                    <span><strong>{scan.domain}</strong><small>{new Date(scan.created_at).toLocaleString()} · {scan.findings?.length ?? 0} findings</small></span>
                    <span className="report-score">{scan.score}/100</span>
                    <span>View →</span>
                  </button>
                ))}</div>
              )}
            </section>
          )}

          {active === "Vulnerabilities" && (
            <section className="content-panel report-panel">
              <div className="panel-title"><div><h3>Vulnerability findings</h3><p>Findings from your latest completed assessment</p></div><button onClick={() => setActive("Website Scanner")}>Run assessment →</button></div>
              {scanResult?.findings?.length ? <div className="finding-list">{scanResult.findings.map((finding) => (
                <article className="finding-card" key={finding.code}><div><span className={`severity ${finding.severity}`}>{finding.severity}</span><strong>{finding.title}</strong></div><p>{finding.description}</p><small>Recommended action: {finding.recommendation}</small></article>
              ))}</div> : <p className="domain-empty">No findings are available yet. Complete a scan of a verified domain to populate this workspace.</p>}
            </section>
          )}

          <div className="lower-grid">
            <section className="content-panel">
              <div className="panel-title">
                <div>
                  <h3>Security activity</h3>
                  <p>Verified findings from completed security scans</p>
                </div>
                <button onClick={() => setActive("Security Reports")}>
                  View reports →
                </button>
              </div>

              <div className="empty-activity">
                <span className="empty-activity-icon">✓</span>
                <strong>No verified security activity yet</strong>
                <p>Completed scans and verified findings will appear here. Sample events are never presented as real security alerts.</p>
              </div>
            </section>

            <section className="content-panel intelligence-panel">
              <div className="panel-title">
                <div>
                  <h3>AI security analyst</h3>
                  <p>Intelligence workspace</p>
                </div>
                <span className="ai-badge">AI</span>
              </div>

              <div className="ai-visual">
                <div className="ai-orbit">✦</div>
              </div>

              <h4>Intelligent security analysis</h4>
              <p className="ai-description">
                Analyze security findings, understand risks and receive
                actionable remediation guidance.
              </p>

              <div className="ai-status">
                <span className="status-dot muted" />
                AI engine not connected
              </div>

              <button
                className="ai-button"
                onClick={() => setActive("Threat Intelligence")}
              >
                Explore intelligence →
              </button>
            </section>
          </div>

          <footer className="footer">
            <span>© 2026 CyberSentryAI</span>
            <span>SECURE BY DESIGN · BUILT FOR DEFENSE</span>
            <span>v0.1.0 · DEVELOPMENT</span>
          </footer>
        </div>
      </section>
    </main>
  );
}
