import { lookup } from "node:dns/promises";
import https from "node:https";
import type { LookupFunction } from "node:dns";
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
    const pinnedLookup = ((_: string, __: unknown, callback: (error: NodeJS.ErrnoException | null, address: string, family: number) => void) => {
      callback(null, address, 4);
    }) as LookupFunction;

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

    request.setTimeout(8000, () => request.destroy(new Error("The website did not respond within 8 seconds.")));
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
  const address = await resolvePinnedAddress(hostname);
  let response = await requestSite(hostname, address, "HEAD");
  if (response.statusCode === 405 || response.statusCode === 501) {
    response = await requestSite(hostname, address, "GET");
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
