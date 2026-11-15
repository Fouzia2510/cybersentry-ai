"use client";

import { useEffect, useState } from "react";

const navigation = [
  { name: "Overview", icon: "◫" },
  { name: "Domain Management", icon: "◎" },
  { name: "Website Scanner", icon: "⌕" },
  { name: "Threat Intelligence", icon: "◈" },
  { name: "Vulnerabilities", icon: "⚠" },
  { name: "Security Reports", icon: "▤" },
];

const events = [
  { type: "Critical", title: "SQL injection exposure", target: "example.test", time: "2 min ago" },
  { type: "High", title: "Missing security headers", target: "demo.test", time: "18 min ago" },
  { type: "Medium", title: "Outdated TLS configuration", target: "sample.test", time: "1 hour ago" },
  { type: "Low", title: "Information disclosure review", target: "portal.test", time: "3 hours ago" },
];

export default function Home() {
  const [active, setActive] = useState("Overview");
  const [url, setUrl] = useState("");
  const [scanning, setScanning] = useState(false);
  const [scanMessage, setScanMessage] = useState("");
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
        if (mounted) await refreshDomains();
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
      setActive("Overview");
    }
  }

  async function validateDomain() {
    if (!url.trim()) {
      setScanMessage("Please enter a website domain first.");
      return;
    }

    setScanning(true);
    setScanMessage("Validating domain format...");

    try {
      const response = await fetch("/api/domains/validate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: url }),
      });
      const result = await response.json();

      if (!response.ok || !result.ok) {
        setScanMessage(result.error || "Domain validation failed.");
        return;
      }

      setScanMessage(
        `Domain format accepted: ${result.normalizedUrl}. Ownership verification and security scanning are not available yet.`
      );
    } catch {
      setScanMessage("Could not reach the validation API. Please try again.");
    } finally {
      setScanning(false);
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

            <button
              className="secondary-button"
              onClick={() => {
                setActive("Overview");
                setScanMessage("");
              }}
            >
              ↻ Refresh dashboard
            </button>
          </div>

          {active !== "Overview" && active !== "Domain Management" && (
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
              <div className="stat-value">--<small>/100</small></div>
              <div className="stat-footer">Awaiting real security assessment</div>
            </article>

            <article className="stat-card">
              <div className="stat-top">
                <span>MONITORED WEBSITES</span>
                <span className="stat-icon cyan">◎</span>
              </div>
              <div className="stat-value">00</div>
              <div className="stat-footer">No websites connected</div>
            </article>

            <article className="stat-card">
              <div className="stat-top">
                <span>VULNERABILITIES</span>
                <span className="stat-icon orange">⚠</span>
              </div>
              <div className="stat-value">--</div>
              <div className="stat-footer">No real scan data available</div>
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

          <section className="scanner-panel">
            <div className="panel-heading">
              <div>
                <div className="eyebrow">WEBSITE SECURITY</div>
                <h3>Website scanner</h3>
                <p>Check whether a domain is valid before connecting it.</p>
              </div>
              <div className="scanner-symbol">⌕</div>
            </div>

            <div className="scan-form">
              <div className="url-input-wrap">
                <span>↗</span>
                <input
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") validateDomain();
                  }}
                  placeholder="Enter a domain (e.g. example.com)"
                  aria-label="Website URL"
                />
              </div>
              <button
                className="scan-button"
                onClick={validateDomain}
                disabled={scanning}
              >
                {scanning ? "Validating..." : "Validate domain →"}
              </button>
            </div>

            {scanMessage && (
              <div className="scan-message" role="status">
                {scanMessage}
              </div>
            )}

            <div className="scan-disclaimer">
              <span>ⓘ</span>
              Domain validation only. No website is contacted, saved, ownership-verified,
              or scanned.
            </div>
          </section>

          <div className="lower-grid">
            <section className="content-panel">
              <div className="panel-title">
                <div>
                  <h3>Security activity</h3>
                  <p>Illustrative events for the dashboard preview</p>
                </div>
                <button onClick={() => setActive("Security Reports")}>
                  View all →
                </button>
              </div>

              <div className="event-list">
                {events.map((event, index) => (
                  <div className="event-row" key={index}>
                    <span className={`event-indicator ${event.type.toLowerCase()}`}>
                      !
                    </span>
                    <div className="event-info">
                      <strong>{event.title}</strong>
                      <small>{event.target}</small>
                    </div>
                    <span className={`severity ${event.type.toLowerCase()}`}>
                      {event.type}
                    </span>
                    <time>{event.time}</time>
                  </div>
                ))}
              </div>
              <div className="demo-label">
                SAMPLE DATA · NOT LIVE SECURITY FINDINGS
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
