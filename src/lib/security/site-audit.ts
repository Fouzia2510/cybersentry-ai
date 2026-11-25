import { lookup } from "node:dns/promises";
import https from "node:https";
import type { TLSSocket } from "node:tls";

export type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";

export type SecurityFinding = {
  code: string;
  severity: FindingSeverity;
  title: string;
  description: string;
  recommendation: string;
  evidence?: string;
  deduction: number;
};

type SiteResponse = {
  statusCode: number;
  headers: import("node:http").IncomingHttpHeaders;
  tlsProtocol: string | null;
  certificateValidTo: string | null;
};

function isPublicIpv4(address: string) {
  const parts = address.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  const [a, b, c] = parts;
  if (
    a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0 && (c === 0 || c === 2)) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
    (a === 203 && b === 0 && c === 113)
  ) return false;
  return true;
}

async function resolvePinnedAddress(hostname: string) {
  const records = await lookup(hostname, { all: true, verbatim: true });
  const ipv4 = records.filter((record) => record.family === 4);
  if (!ipv4.length) throw new Error("The domain does not resolve to a public IPv4 address.");
  if (ipv4.some((record) => !isPublicIpv4(record.address))) {
    throw new Error("The domain resolves to a non-public network address and cannot be scanned.");
  }
  return ipv4[0].address;
}

function requestSite(hostname: string, address: string, method: "HEAD" | "GET"): Promise<SiteResponse> {
  return new Promise((resolve, reject) => {
    const pinnedLookup = ((_: string, options: unknown, callback: (...args: unknown[]) => void) => {
      // Node may request either the single-address or all-address lookup shape.
      if (typeof options === "object" && options !== null && "all" in options && (options as { all?: boolean }).all) {
        callback(null, [{ address, family: 4 }]);
      } else {
        callback(null, address, 4);
      }
    }) as NonNullable<import("node:https").RequestOptions["lookup"]>;

    const agent = new https.Agent({ keepAlive: false, lookup: pinnedLookup });
    const request = https.request({
      hostname,
      port: 443,
      path: "/",
      method,
      agent,
      lookup: pinnedLookup,
      servername: hostname,
      timeout: 8000,
      maxHeaderSize: 16 * 1024,
      headers: {
        "User-Agent": "CyberSentryAI-SecurityAudit/1.0",
        Accept: "text/html,application/xhtml+xml",
        ...(method === "GET" ? { Range: "bytes=0-0" } : {}),
      },
    }, (response) => {
      const socket = response.socket as TLSSocket;
      const certificate = socket.getPeerCertificate();
      const result: SiteResponse = {
        statusCode: response.statusCode ?? 0,
        headers: response.headers,
        tlsProtocol: socket.getProtocol() ?? null,
        certificateValidTo: certificate?.valid_to ?? null,
      };
      response.destroy();
      agent.destroy();
      resolve(result);
    });

    request.setTimeout(8000, () => request.destroy(new Error("HTTPS connection timed out after 8 seconds. The domain resolved, but no web-server response completed on port 443. Confirm HTTPS hosting is configured and reachable.")));
    request.once("error", (error) => {
      agent.destroy();
      reject(error);
    });
    request.end();
  });
}

function hasHeader(headers: SiteResponse["headers"], name: string) {
  const value = headers[name.toLowerCase()];
  return typeof value === "string" ? value.trim().length > 0 : Array.isArray(value) && value.length > 0;
}

function finding(
  code: string,
  severity: FindingSeverity,
  title: string,
  description: string,
  recommendation: string,
  deduction: number,
  evidence?: string,
): SecurityFinding {
  return { code, severity, title, description, recommendation, deduction, ...(evidence ? { evidence } : {}) };
}

export async function auditVerifiedWebsite(hostname: string) {
  let address: string;
  try {
    address = await resolvePinnedAddress(hostname);
  } catch (error) {
    const code = error && typeof error === "object" && "code" in error ? String((error as { code?: unknown }).code) : "";
    if (code === "ENOTFOUND" || code === "EAI_AGAIN") throw new Error("DNS lookup failed or is temporarily unavailable. Confirm the domain DNS records and try again.");
    throw error;
  }
  // Inspect the same response path browsers use. Some hosting platforms
  // return different security headers for HEAD than for a normal page GET.
  let response: SiteResponse;
  try {
    response = await requestSite(hostname, address, "GET");
  } catch (error) {
    const code = error && typeof error === "object" && "code" in error ? String((error as { code?: unknown }).code) : "";
    if (code === "ECONNREFUSED") throw new Error("The domain resolved, but its HTTPS server refused the connection on port 443. Configure an HTTPS web server before scanning.");
    if (code === "CERT_HAS_EXPIRED" || code === "CERT_INVALID" || code === "ERR_TLS_CERT_ALTNAME_INVALID") throw new Error("The HTTPS connection failed certificate validation. Check the site TLS certificate and hostname.");
    if (error instanceof Error && error.message.includes("timed out")) throw error;
    throw new Error("Could not establish a safe HTTPS connection. Check that a website is hosted on this domain and HTTPS is enabled.");
  }
  if (response.statusCode === 405 || response.statusCode === 501) {
    response = await requestSite(hostname, address, "HEAD");
  }

  // A reachable error page or redirect is not a completed security assessment.
  // Do not award a misleading score from headers on an authentication/error page
  // or silently follow redirects to a different host.
  if (response.statusCode >= 300 && response.statusCode < 400) {
    throw new Error(`The HTTPS server redirected this domain (HTTP ${response.statusCode}). Configure the verified hostname to serve the website directly over HTTPS, then scan again.`);
  }
  if (response.statusCode < 200 || response.statusCode >= 300) {
    throw new Error(`The HTTPS server returned HTTP ${response.statusCode}. The page could not be assessed reliably; fix the website response and try again.`);
  }

  const findings: SecurityFinding[] = [];
  const headers = response.headers;
  const csp = typeof headers["content-security-policy"] === "string" ? headers["content-security-policy"] : "";

  if (!hasHeader(headers, "strict-transport-security")) {
    findings.push(finding("missing-hsts", "medium", "HTTP Strict Transport Security is missing", "The HTTPS response does not include a Strict-Transport-Security header.", "Configure HSTS with an appropriate max-age. Add includeSubDomains only after confirming all subdomains support HTTPS.", 10));
  }
  if (!csp) {
    findings.push(finding("missing-csp", "medium", "Content Security Policy is missing", "No Content-Security-Policy header was observed on the homepage response.", "Deploy a tested Content Security Policy that restricts script, object, base, and frame sources.", 12));
  }
  if (!hasHeader(headers, "x-content-type-options")) {
    findings.push(finding("missing-nosniff", "low", "MIME-sniffing protection is missing", "The response does not include X-Content-Type-Options.", "Set X-Content-Type-Options: nosniff.", 4));
  }
  if (!hasHeader(headers, "x-frame-options") && !/frame-ancestors/i.test(csp)) {
    findings.push(finding("missing-frame-protection", "low", "Clickjacking protection is missing", "Neither X-Frame-Options nor a CSP frame-ancestors directive was observed.", "Set a suitable frame-ancestors CSP directive, or X-Frame-Options where legacy support is required.", 5));
  }
  if (!hasHeader(headers, "referrer-policy")) {
    findings.push(finding("missing-referrer-policy", "low", "Referrer Policy is missing", "The response does not define how much referrer information browsers should send.", "Set Referrer-Policy: strict-origin-when-cross-origin or a stricter policy suitable for the application.", 3));
  }
  if (!hasHeader(headers, "permissions-policy")) {
    findings.push(finding("missing-permissions-policy", "info", "Permissions Policy is not defined", "The response does not include a Permissions-Policy header.", "Explicitly disable browser capabilities that the site does not use, such as camera, microphone, and geolocation.", 1));
  }
  if (response.tlsProtocol && !["TLSv1.2", "TLSv1.3"].includes(response.tlsProtocol)) {
    findings.push(finding("legacy-tls", "high", "Legacy TLS protocol observed", `The TLS connection negotiated ${response.tlsProtocol}.`, "Configure the web server to support TLS 1.2 or TLS 1.3 and disable obsolete protocol versions.", 20, response.tlsProtocol));
  }
  if (response.certificateValidTo) {
    const expiry = Date.parse(response.certificateValidTo);
    const daysRemaining = Math.floor((expiry - Date.now()) / 86_400_000);
    if (Number.isFinite(expiry) && daysRemaining < 30) {
      findings.push(finding("certificate-expiring", daysRemaining < 7 ? "high" : "medium", "TLS certificate is expiring soon", `The presented TLS certificate expires in approximately ${Math.max(0, daysRemaining)} days.`, "Renew the TLS certificate and verify automatic renewal is working.", daysRemaining < 7 ? 15 : 8, response.certificateValidTo));
    }
  }

  const score = Math.max(0, 100 - findings.reduce((total, item) => total + item.deduction, 0));
  return {
    domain: hostname,
    checkedAt: new Date().toISOString(),
    httpStatus: response.statusCode,
    tlsProtocol: response.tlsProtocol,
    score,
    findings,
    summary: {
      total: findings.length,
      critical: findings.filter((item) => item.severity === "critical").length,
      high: findings.filter((item) => item.severity === "high").length,
      medium: findings.filter((item) => item.severity === "medium").length,
      low: findings.filter((item) => item.severity === "low").length,
      info: findings.filter((item) => item.severity === "info").length,
    },
    scope: "Passive HTTPS configuration checks for the verified domain homepage. No exploitation or intrusive testing is performed.",
  };
}
