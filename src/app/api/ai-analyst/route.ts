import { NextResponse } from "next/server";
import { getAccessToken, getAuthenticatedUser, isSameOriginRequest } from "@/lib/supabase-rest";

type InputFinding = {
  severity?: unknown;
  title?: unknown;
  description?: unknown;
  recommendation?: unknown;
  evidence?: unknown;
};

const asText = (value: unknown, max: number) =>
  typeof value === "string" ? value.slice(0, max) : "";

export async function POST(request: Request) {
  if (!isSameOriginRequest(request)) return NextResponse.json({ error: "Cross-origin request rejected." }, { status: 403 });
  const token = await getAccessToken();
  if (!token) return NextResponse.json({ error: "Sign in is required." }, { status: 401 });
  const user = await getAuthenticatedUser(token);
  if (!user) return NextResponse.json({ error: "Your session has expired. Sign in again." }, { status: 401 });

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON request." }, { status: 400 });
  }

  if (!body || typeof body !== "object" || !("domain" in body) || typeof body.domain !== "string" || !("findings" in body) || !Array.isArray(body.findings)) {
    return NextResponse.json({ error: "Provide a scan report to analyze." }, { status: 400 });
  }

  const payload = body as { domain: string; score?: unknown; findings: unknown[] };
  const domain = payload.domain.slice(0, 253);
  const score = Number(payload.score);
  const findings = (payload.findings as InputFinding[]).slice(0, 30).map((finding) => ({
    severity: asText(finding?.severity, 20),
    title: asText(finding?.title, 200),
    description: asText(finding?.description, 600),
    recommendation: asText(finding?.recommendation, 600),
    evidence: asText(finding?.evidence, 300),
  }));

  const rank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  const ordered = findings.slice().sort((a, b) =>
    (rank[a.severity.toLowerCase()] ?? -1) - (rank[b.severity.toLowerCase()] ?? -1)
  ).reverse();
  const counts = ["critical", "high", "medium", "low", "info"]
    .map((severity) => `${severity}: ${findings.filter((finding) => finding.severity.toLowerCase() === severity).length}`)
    .join(" · ");

  const header = `RULE-BASED SECURITY REVIEW (offline)\n\nDomain: ${domain}\nScore: ${Number.isFinite(score) ? score : "unknown"}/100\n\n`;
  const guidance = findings.length
    ? `Prioritize findings by severity. Address critical and high severity items first, then medium and low findings.\n\n${ordered.map((finding, index) => `${index + 1}. [${finding.severity}] ${finding.title}\n   Observed: ${finding.description || finding.evidence || "No detail supplied."}\n   Recommended action: ${finding.recommendation || "Review this configuration and apply the vendor-recommended secure setting."}`).join("\n\n")}`
    : "No findings were recorded in this passive assessment. This is encouraging, but it does not establish that the site is vulnerability-free. Only controls included in this scan were assessed.\n\nRecommended next steps:\n• Keep HTTPS enabled and renew certificates before expiry.\n• Review security headers and configuration after changes.\n• Use authorized testing for application logic and access controls.";

  const analysis = `${header}${guidance}\n\nFinding counts: ${counts}\n\nThis deterministic review uses only report data; no external AI service was used.`;
  return NextResponse.json({ ok: true, analysis, mode: "rule-based", notice: "Offline analysis only. No external AI service or paid API is used." });
}
