"use client";

import { useState } from "react";

const navigation = [
  { name: "Overview", icon: "◫" },
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
  const [refreshing, setRefreshing] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);
  const [refreshMessage, setRefreshMessage] = useState("");

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
          ? "Dashboard checked successfully. Supabase API is reachable."
          : "Dashboard checked. Supabase is not configured or could not be reached."
      );
      setActive("Overview");
      setScanMessage("");
    } catch {
      setRefreshMessage("Unable to refresh right now. Check your connection and try again.");
    } finally {
      setRefreshing(false);
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
            <div className="top-avatar">F</div>
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

          {active !== "Overview" && (
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
                  <p>Verified activity from connected security services</p>
                </div>
                <button onClick={() => setActive("Security Reports")}>
                  View all →
                </button>
              </div>

              <div className="empty-activity">
                <span className="empty-activity-icon">✓</span>
                <strong>No verified security activity yet</strong>
                <p>Connect and scan an authorized website to see real findings here. Sample events are intentionally hidden.</p>
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
