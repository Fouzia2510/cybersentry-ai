import { NextResponse } from "next/server";
import { getAccessToken, getAuthenticatedUser, isSameOriginRequest } from "@/lib/supabase-rest";

export async function POST(request: Request) {
  if (!isSameOriginRequest(request)) return NextResponse.json({ error: "Cross-origin request rejected." }, { status: 403 });
  const token = await getAccessToken();
  if (!token) return NextResponse.json({ error: "Sign in is required." }, { status: 401 });
  const user = await getAuthenticatedUser(token);
  if (!user) return NextResponse.json({ error: "Your session has expired. Sign in again." }, { status: 401 });
  const key = process.env.OPENAI_API_KEY;
  if (!key) return NextResponse.json({ error: "AI Analyst is not configured yet. Add OPENAI_API_KEY in Netlify environment variables." }, { status: 503 });
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
  try {
    const response = await fetch("https://api.openai.com/v1/responses", {
      method: "POST", headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
      body: JSON.stringify({ model: "gpt-4.1-mini", input: [
        { role: "system", content: "You are a defensive website security analyst. Analyze only the supplied passive scan results. Do not claim exploitation, active attacks, or unobserved vulnerabilities. Give concise prioritized risk explanation, impact in plain language, remediation steps, and a short executive summary. Clearly note limitations." },
        { role: "user", content: JSON.stringify({ domain, score: Number.isFinite(score) ? score : null, findings }) }
      ], max_output_tokens: 700 }),
      cache: "no-store"
    });
    if (!response.ok) {\n      const providerData = await response.json().catch(() => null);\n      const providerMessage = typeof providerData?.error?.message === "string" ? providerData.error.message.slice(0, 300) : "Unknown provider error";\n      const providerCode = typeof providerData?.error?.code === "string" ? providerData.error.code.slice(0, 80) : undefined;\n      return NextResponse.json({ error: `AI provider error (${response.status}): ${providerMessage}${providerCode ? ` [${providerCode}]` : ""}` }, { status: 502 });\n    }
    const data = await response.json();
    const text = (data.output || []).flatMap((o: any) => o.content || []).find((c: any) => c.type === "output_text")?.text;
    if (!text) return NextResponse.json({ error: "AI provider returned no analysis." }, { status: 502 });
    return NextResponse.json({ ok: true, analysis: text });
  } catch { return NextResponse.json({ error: "AI analysis service could not be reached." }, { status: 502 }); }
}
