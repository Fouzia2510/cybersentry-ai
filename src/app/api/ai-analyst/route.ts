import { NextResponse } from "next/server";
import { getAccessToken, getAuthenticatedUser, isSameOriginRequest } from "@/lib/supabase-rest";

export async function POST(request: Request) {
  if (!isSameOriginRequest(request)) return NextResponse.json({ error: "Cross-origin request rejected." }, { status: 403 });
  const token = await getAccessToken();
  if (!token) return NextResponse.json({ error: "Sign in is required." }, { status: 401 });
  const user = await getAuthenticatedUser(token);
  if (!user) return NextResponse.json({ error: "Your session has expired. Sign in again." }, { status: 401 });
  let body: any;
  try { body = await request.json(); } catch { return NextResponse.json({ error: "Invalid JSON request." }, { status: 400 }); }
  if (!body || typeof body !== "object" || typeof body.domain !== "string" || !Array.isArray(body.findings)) return NextResponse.json({ error: "Provide a scan report to analyze." }, { status: 400 });
  const domain = body.domain.slice(0, 253);
  const score = Number(body.score);
  const findings = body.findings.slice(0, 30).map((f: any) => ({
    severity: String(f?.severity ?? "").slice(0, 20), title: String(f?.title ?? "").slice(0, 200),
    description: String(f?.description ?? "").slice(0, 600), recommendation: String(f?.recommendation ?? "").slice(0, 600),
    evidence: String(f?.evidence ?? "").slice(0, 300)
  }));
  const ruleBasedAnalysis = () => {
    const rank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    const ordered = findings.slice().sort((a: any, b: any) => (rank[String(b.severity).toLowerCase()] ?? -1) - (rank[String(a.severity).toLowerCase()] ?? -1));
    const counts = ["critical", "high", "medium", "low", "info"].map(s => `${s}: ${findings.filter((f: any) => String(f.severity).toLowerCase() === s).length}`).join(" · ");
    if (!findings.length) return `RULE-BASED SECURITY REVIEW (offline fallback)\n\nDomain: ${domain}\nScore: ${Number.isFinite(score) ? score : "unknown"}/100\n\nNo findings were recorded in this passive assessment. This is encouraging, but it does not establish that the site is vulnerability-free. Only controls included in this scan were assessed.\n\nRecommended next steps:\n• Keep HTTPS enabled and renew certificates before expiry.\n• Review security headers and configuration after changes.\n• Use authorized testing for application logic and access controls.\n\nFinding counts: ${counts}\n\nThis deterministic review uses only report data; no external AI service was used.`;
    const items = ordered.map((f: any, i: number) => `${i + 1}. [${f.severity}] ${f.title}\n   Observed: ${f.description || f.evidence || "No detail supplied."}\n   Recommended action: ${f.recommendation || "Review this configuration and apply the vendor-recommended secure setting."}`).join("\n\n");
    return `RULE-BASED SECURITY REVIEW (offline fallback)\n\nDomain: ${domain}\nScore: ${Number.isFinite(score) ? score : "unknown"}/100\n\nPrioritize findings by severity. Address critical and high severity items first, then medium and low findings.\n\n${items}\n\nFinding counts: ${counts}\n\nThis deterministic review uses only report data; no external AI service was used.`;
  };
  return NextResponse.json({ ok: true, analysis: ruleBasedAnalysis(), mode: "rule-based", notice: "Offline analysis only. No external AI service or paid API is used." });
}
