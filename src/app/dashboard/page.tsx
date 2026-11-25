"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

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
  const router = useRouter();
  const [active, setActive] = useState("Overview");
  const [authChecking, setAuthChecking] = useState(true);
  const [authError, setAuthError] = useState("");
  const [profileMenuOpen, setProfileMenuOpen] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [platformScanning, setPlatformScanning] = useState(false);
  const [platformScanMessage, setPlatformScanMessage] = useState("");
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
  const [vulnFilter, setVulnFilter] = useState("all");
  const [selectedReport, setSelectedReport] = useState<ScanRecord | null>(null);
  const [aiAnalysis, setAiAnalysis] = useState("");
  const [aiBusy, setAiBusy] = useState(false);
  const [aiError, setAiError] = useState("");

  async function analyzeReport(scan: ScanRecord) {
    setAiBusy(true); setAiError(""); setAiAnalysis("");
    try {
      const response = await fetch("/api/ai-analyst", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ domain: scan.domain, score: scan.score, findings: scan.findings }) });
      const result = await response.json();
      if (!response.ok) { setAiError(result.error || "Analysis failed."); return; }
      setAiAnalysis(result.analysis || "No analysis returned.");
    } catch { setAiError("Could not connect to AI Analyst."); } finally { setAiBusy(false); }
  }

  async function refreshScans() {
    setScanHistoryError("");
    try {
      const [response, platformResponse] = await Promise.all([
        fetch("/api/scans", { cache: "no-store" }),
        fetch("/api/platform-scan", { cache: "no-store" }),
      ]);
      const [result, platformResult] = await Promise.all([response.json(), platformResponse.json()]);
      if (!response.ok) {
        setScanHistoryError(result.error || "Could not load scan history.");
        return;
      }
      const combined = [
        ...(result.scans || []),
        ...(platformResponse.ok ? (platformResult.scans || []).map((scan: ScanRecord) => ({ ...scan, status: "completed" })) : []),
      ].sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at));
      setScans(combined);
      if (combined[0]) setScanResult(combined[0]);
    } catch {
      setScanHistoryError("Could not reach the scan history service.");
    }
  }

  async function startPlatformScan() {
    setPlatformScanning(true);
    setPlatformScanMessage("Running a restricted passive scan of the CyberSentryAI platform...");
    try {
      const response = await fetch("/api/platform-scan", { method: "POST", cache: "no-store" });
      const responseText = await response.text();
      let result: {
        error?: string;
        scan?: {
          id?: string | null;
          domain: string;
          score: number;
          findings: ScanFinding[];
          summary: Record<string, number>;
          httpStatus: number;
          tlsProtocol: string | null;
          checkedAt: string;
        };
      };
      try {
        result = JSON.parse(responseText) as typeof result;
      } catch {
        throw new Error(`Scan service returned an unexpected response (HTTP ${response.status}).`);
      }
      if (!response.ok) {
        setPlatformScanMessage(result.error || `Platform self-scan failed (HTTP ${response.status}).`);
        return;
      }
      if (!result.scan) {
        throw new Error("Scan service returned no assessment report.");
      }
      const scan: ScanRecord = {
        id: result.scan.id ?? `platform-${result.scan.checkedAt}`,
        domain: result.scan.domain,
        score: result.scan.score,
        status: "completed",
        findings: result.scan.findings,
        summary: result.scan.summary,
        http_status: result.scan.httpStatus,
        tls_protocol: result.scan.tlsProtocol,
        created_at: result.scan.checkedAt,
      };
      setScanResult(scan);
      setScans((current) => [scan, ...current.filter((item) => item.id !== scan.id)]);
      setPlatformScanMessage("Platform assessment completed and saved to Security Reports.");
    } catch (error) {
      setPlatformScanMessage(error instanceof Error ? error.message : "Could not reach the platform scan service.");
    } finally {
      setPlatformScanning(false);
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

  async function createDomainChallenge(domainToVerify?: string) {
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
        body: JSON.stringify({ domain: domainToVerify ?? domainInput }),
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
        if (response.status === 401) {
          router.replace("/login?next=/dashboard");
          return;
        }
        if (!response.ok) {
          throw new Error("We could not verify your workspace session. Please refresh and try again.");
        }
        const session = await response.json();
        if (!session.authenticated || !session.user) {
          router.replace("/login?next=/");
          return;
        }
        if (mounted) setUserEmail(session.user.email ?? null);
        if (mounted) {
          await Promise.all([refreshDomains(), refreshScans()]);
          setAuthChecking(false);
        }
      } catch (error) {
        if (mounted) {
          setAuthError(error instanceof Error ? error.message : "Authentication service is unavailable.");
          setAuthChecking(false);
          setDomainLoading(false);
        }
      }
    }
    void loadSession();
    return () => { mounted = false; };
  }, [router]);

  async function handleLogout() {
    setProfileMenuOpen(false);
    try {
      await fetch("/api/auth/logout", { method: "POST" });
    } finally {
      setUserEmail(null);
      setDomains([]);
      setScans([]);
      setScanResult(null);
      router.replace("/login");
      router.refresh();
    }
  }

  if (authChecking) {
    return (
      <main className="auth-checking-shell" aria-live="polite">
        <div className="auth-checking-card">
          <span className="auth-checking-mark">C</span>
          <strong>Securing your workspace</strong>
          <span>Verifying your administrator session...</span>
        </div>
      </main>
    );
  }

  if (authError) {
    return (
      <main className="auth-checking-shell">
        <div className="auth-checking-card">
          <span className="auth-checking-mark">!</span>
          <strong>Workspace sign-in could not be verified</strong>
          <span>{authError}</span>
          <button className="auth-submit" onClick={() => window.location.reload()}>Try again</button>
          <a className="auth-back" href="/login">Go to sign in</a>
        </div>
      </main>
    );
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
            <div className="avatar">{userEmail?.charAt(0).toUpperCase() || "A"}</div>
            <div className="profile-copy">
              <strong>Workspace account</strong>
              <small>{userEmail}</small>
            </div>
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
            <span className="environment">
              <span className="status-dot" />
              DEVELOPMENT
            </span>
            <div className="account-menu-wrap">
              <button
                className="top-avatar account-menu-trigger"
                type="button"
                aria-label="Open account menu"
                aria-haspopup="menu"
                aria-expanded={profileMenuOpen}
                onClick={() => setProfileMenuOpen((open) => !open)}
              >
                {userEmail?.charAt(0).toUpperCase() || "A"}
                <span className="account-menu-caret">▾</span>
              </button>
              {profileMenuOpen && (
                <div className="account-menu" role="menu" aria-label="Account menu">
                  <div className="account-menu-heading">
                    <strong>Workspace account</strong>
                    <span>{userEmail}</span>
                    <small><i /> Signed in</small>
                  </div>
                  <button type="button" role="menuitem" onClick={handleLogout}>
                    <span>↪</span> Sign out
                  </button>
                </div>
              )}
            </div>
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

          {active !== "Overview" && active !== "Domain Management" && active !== "Website Scanner" && active !== "Security Reports" && active !== "Vulnerabilities" && active !== "Threat Intelligence" && (
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
                    <button onClick={() => void createDomainChallenge()} disabled={domainActionBusy || !domainInput.trim()}>
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
                    <button type="button" className="domain-row domain-row-button" key={domain.id} onClick={() => void createDomainChallenge(domain.domain)} disabled={domainActionBusy || domain.verificationStatus === "verified"} aria-label={`Open DNS verification for ${domain.domain}`}>
                      <span>
                        <strong>{domain.domain}</strong>
                        <small>Added {new Date(domain.createdAt).toLocaleDateString()}</small>
                      </span>
                      <span className={domain.verificationStatus === "verified" ? "domain-status verified" : "domain-status pending"}>
                        {domain.verificationStatus === "pending" ? "pending · Verify →" : "verified"}
                      </span>
                    </button>
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

          {active === "Overview" && scans.length > 0 && (() => {
            const latestByDomain = new Map<string, ScanRecord>();
            for (const scan of scans) if (!latestByDomain.has(scan.domain)) latestByDomain.set(scan.domain, scan);
            const alerts = Array.from(latestByDomain.values()).flatMap((latest) => {
              const previous = scans.filter((s) => s.domain === latest.domain && s.id !== latest.id && Date.parse(s.created_at) < Date.parse(latest.created_at)).sort((a,b)=>Date.parse(b.created_at)-Date.parse(a.created_at))[0];
              if (!previous) return [];
              const oldCodes = new Set((previous.findings || []).map((f) => f.code));
              const newFindings = (latest.findings || []).filter((f) => !oldCodes.has(f.code));
              const worsened = latest.score < previous.score;
              return newFindings.length || worsened ? [{domain: latest.domain, latest, previous, newFindings, worsened}] : [];
            });
            return <section className="content-panel report-panel"><div className="panel-title"><div><h3>Assessment change alerts</h3><p>Changes detected by comparing saved scans — not continuous monitoring</p></div><button onClick={() => setActive("Security Reports")}>Review reports →</button></div>
              {alerts.length ? <div className="finding-list">{alerts.map((alert) => <article className="finding-card" key={alert.domain}><div><span className="severity high">Change</span><strong>{alert.domain}</strong></div><p>{alert.newFindings.length} new finding(s) since the previous saved assessment. Score: {alert.previous.score} → {alert.latest.score}{alert.worsened ? " (declined)" : ""}.</p>{alert.newFindings.slice(0,5).map((f)=><p key={f.code}><strong>{f.severity}:</strong> {f.title}</p>)}<button className="scan-button" onClick={()=>{setSelectedReport(alert.latest);setActive("Security Reports");}}>Open latest report →</button></article>)}</div> : <p className="domain-empty">No new findings or score declines compared with the previous saved report for each domain.</p>}
            </section>;
          })()}
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
                  <input aria-label="Platform self-scan target" value="cybersentry-ai-fouzia2510.netlify.app · Platform self-scan" readOnly />
                </div>
                <button className="scan-button" onClick={startPlatformScan} disabled={platformScanning}>
                  {platformScanning ? "Assessing platform..." : "Run platform self-scan →"}
                </button>
              </div>
              {platformScanMessage && <div className="scan-message" role="status">{platformScanMessage}</div>}
              <p className="domain-note">Platform self-scan is restricted to this CyberSentryAI Netlify hostname. Other websites still require DNS ownership verification.</p>

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
            <section id="security-reports-panel" className="content-panel report-panel">
              <div className="panel-title"><div><h3>Security assessment reports</h3><p>Saved reports from your completed assessments</p></div><button onClick={refreshScans}>↻ Refresh</button></div>
              {scanHistoryError && <p className="domain-error" role="alert">{scanHistoryError}</p>}
              {scans.length === 0 ? <p className="domain-empty">No saved reports yet. Run an assessment to create your first report.</p> : selectedReport ? (
                <div className="content-panel">
                  <div className="panel-title"><div><h3>Report details</h3><p>{selectedReport.domain} · {new Date(selectedReport.created_at).toLocaleString()}</p></div><button onClick={()=>setSelectedReport(null)}>Back to history</button></div>
                  <div className="scan-result-heading"><div><span className="eyebrow">PASSIVE ASSESSMENT</span><h4>{selectedReport.domain}</h4><p>HTTP {selectedReport.http_status ?? "—"} · {selectedReport.tls_protocol ?? "TLS details unavailable"}</p></div><div className="scan-score"><strong>{selectedReport.score}</strong><span>/100</span></div></div>
                  <div className="finding-summary">{(["critical","high","medium","low","info"] as const).map(s=><span key={s} className={`finding-count ${s}`}>{selectedReport.summary?.[s] ?? 0} {s}</span>)}</div>
                  <div className="finding-list">{(selectedReport.findings||[]).map(f=><article className="finding-card" key={f.code}><div><span className={`severity ${f.severity}`}>{f.severity}</span><strong>{f.title}</strong></div><p>{f.description}</p>{f.evidence&&<p><strong>Evidence:</strong> {f.evidence}</p>}<small>Recommended action: {f.recommendation}</small></article>)}</div>
                  <button className="scan-button" onClick={()=>window.print()}>Print / Save PDF</button>
                  <div className="content-panel"><div className="panel-title"><div><h3>AI Security Analyst</h3><p>AI interpretation of this passive scan report</p></div></div><button className="scan-button" disabled={aiBusy} onClick={() => analyzeReport(selectedReport)}>{aiBusy ? "Analyzing report..." : "✦ Analyze with AI"}</button>{aiError && <p className="domain-error" role="alert">{aiError}</p>}{aiAnalysis && <article className="finding-card"><p style={{whiteSpace:"pre-wrap"}}>{aiAnalysis}</p></article>}</div>
                  {(()=>{const previous=scans.filter(s=>s.domain===selectedReport.domain&&s.id!==selectedReport.id&&Date.parse(s.created_at)<Date.parse(selectedReport.created_at)).sort((a,b)=>Date.parse(b.created_at)-Date.parse(a.created_at))[0];return previous?<div className="domain-note"><strong>Previous assessment comparison:</strong> Score {previous.score} → {selectedReport.score} ({selectedReport.score-previous.score>=0?"+":""}{selectedReport.score-previous.score} points). Findings: {previous.findings?.length??0} → {selectedReport.findings?.length??0}. Comparison uses the previous saved assessment for this domain.</div>:<p className="domain-note">No earlier report for this domain is available to compare.</p>})()}
                </div>
              ) : (
                <div className="report-list">{scans.map((scan) => (
                  <button className="report-row" key={scan.id} onClick={() => setSelectedReport(scan)}>
                    <span><strong>{scan.domain}</strong><small>{new Date(scan.created_at).toLocaleString()} · {scan.findings?.length ?? 0} findings</small></span>
                    <span className="report-score">{scan.score}/100</span><span>Details →</span>
                  </button>
                ))}</div>
              )}
            </section>
          )}

          {active === "Threat Intelligence" && (
            <section className="content-panel report-panel">
              <div className="panel-title"><div><h3>Threat Intelligence</h3><p>Local intelligence derived only from your completed security assessments</p></div><button onClick={refreshScans}>↻ Refresh</button></div>
              {scanHistoryError && <p className="domain-error" role="alert">{scanHistoryError}</p>}
              {scans.length === 0 ? <p className="domain-empty">No assessment data yet. Run a passive scan to populate this intelligence workspace. External threat feeds are not connected.</p> : (() => {
                const items = scans.flatMap((scan) => (scan.findings || []).map((finding) => ({ ...finding, domain: scan.domain, date: scan.created_at }))).sort((a,b)=>Date.parse(b.date)-Date.parse(a.date));
                const counts = { critical: items.filter(i=>i.severity==="critical").length, high: items.filter(i=>i.severity==="high").length, medium: items.filter(i=>i.severity==="medium").length, low: items.filter(i=>i.severity==="low").length, info: items.filter(i=>i.severity==="info").length };
                return <>
                  <div className="finding-summary">{(["critical","high","medium","low","info"] as const).map((severity)=><span key={severity} className={`finding-count ${severity}`}>{counts[severity]} {severity}</span>)}</div>
                  <p className="domain-note">These are observed configuration findings, not confirmed active attacks or live threat-feed intelligence.</p>
                  {items.length ? <div className="finding-list">{items.slice(0,30).map((item,index)=><article className="finding-card" key={item.domain+item.code+item.date+index}><div><span className={`severity ${item.severity}`}>{item.severity}</span><strong>{item.title}</strong></div><p><strong>Domain:</strong> {item.domain} · <strong>Observed:</strong> {new Date(item.date).toLocaleString()}</p><p>{item.description}</p><small>Recommended action: {item.recommendation}</small></article>)}</div>:<p className="domain-empty">No findings recorded in completed assessments.</p>}
                </>;
              })()}
            </section>
          )}

          {active === "Vulnerabilities" && (
            <section className="content-panel report-panel">
              <div className="panel-title"><div><h3>Vulnerability findings</h3><p>Prioritized findings from your latest completed assessment — passive checks only</p></div><button onClick={() => setActive("Website Scanner")}>Run assessment →</button></div>
              {scanResult?.findings?.length ? (() => {
                const severityOrder = ["critical", "high", "medium", "low", "info"];
                const filtered = scanResult.findings.filter((f) => vulnFilter === "all" || f.severity.toLowerCase() === vulnFilter);
                const sorted = [...filtered].sort((a,b) => severityOrder.indexOf(a.severity.toLowerCase()) - severityOrder.indexOf(b.severity.toLowerCase()) || a.title.localeCompare(b.title));
                return <>
                  <div className="finding-summary">{severityOrder.map((severity) => <button type="button" key={severity} className={`finding-count ${severity}`} onClick={() => setVulnFilter(severity)}>{scanResult.summary?.[severity] ?? scanResult.findings.filter(f=>f.severity.toLowerCase()===severity).length} {severity}</button>)}</div>
                  <div className="scan-form"><div className="url-input-wrap"><select aria-label="Filter vulnerabilities by severity" value={vulnFilter} onChange={(event)=>setVulnFilter(event.target.value)}><option value="all">All severities</option>{severityOrder.map(s=><option key={s} value={s}>{s[0].toUpperCase()+s.slice(1)}</option>)}</select></div><span className="refresh-meta">{filtered.length} finding(s) · {scanResult.domain}</span></div>
                  {sorted.length ? <div className="finding-list">{sorted.map((finding) => (
                    <article className="finding-card" key={finding.code}><div><span className={`severity ${finding.severity}`}>{finding.severity}</span><strong>{finding.title}</strong></div><p>{finding.description}</p>{finding.evidence && <p><strong>Evidence:</strong> {finding.evidence}</p>}<small>Recommended action: {finding.recommendation}</small></article>
                  ))}</div> : <p className="domain-empty">No findings match this severity filter.</p>}
                  <p className="domain-note">Findings describe observed configuration weaknesses, not proof of exploitation. Severity is based on the assessment rule, not a live threat signal.</p>
                </>;
              })() : <p className="domain-empty">No findings are available yet. Complete a scan to populate this workspace.</p>}
            </section>
          )}

          <div className="lower-grid">
            <section className="content-panel">
              <div className="panel-title">
                <div>
                  <h3>Security activity</h3>
                  <p>Verified findings from completed security scans</p>
                </div>
                <button type="button" aria-label="Open Security Reports" onClick={() => { setSelectedReport(null); setActive("Security Reports"); document.getElementById("security-reports-panel")?.scrollIntoView({ behavior: "smooth", block: "start" }); }}>
                  View reports →
                </button>
              </div>

              {scans.length === 0 ? (
                <div className="empty-activity">
                  <span className="empty-activity-icon">✓</span>
                  <strong>No verified security activity yet</strong>
                  <p>Completed scans and verified findings will appear here. Sample events are never presented as real security alerts.</p>
                </div>
              ) : (
                <div className="report-list activity-list">
                  {scans.slice(0, 5).map((scan) => (
                    <button className="report-row" key={scan.id} onClick={() => { setScanResult(scan); setSelectedScanDomain(scan.domain); setActive("Website Scanner"); }}>
                      <span><strong>{scan.domain}</strong><small>{new Date(scan.created_at).toLocaleString()} · {scan.findings?.length ?? 0} findings</small></span>
                      <span className="report-score">{scan.score}/100</span>
                      <span>View →</span>
                    </button>
                  ))}
                </div>
              )}
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
