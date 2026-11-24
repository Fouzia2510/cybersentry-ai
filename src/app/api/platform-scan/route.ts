import { NextResponse } from "next/server";
import { auditVerifiedWebsite } from "@/lib/security/site-audit";
import { getAccessToken, getAuthenticatedUser, isSameOriginRequest, supabaseUserRequest } from "@/lib/supabase-rest";


const PLATFORM_HOST = "cybersentry-ai-fouzia2510.netlify.app";

export async function POST(request: Request) {
  if (!isSameOriginRequest(request)) return NextResponse.json({ error: "Cross-origin request rejected." }, { status: 403 });
  const accessToken = await getAccessToken();
  if (!accessToken) return NextResponse.json({ error: "Sign in is required." }, { status: 401 });
  try {
    const user = await getAuthenticatedUser(accessToken);
    if (!user) return NextResponse.json({ error: "Your session has expired. Sign in again." }, { status: 401 });
    // Only scan this site's production hostname or a Netlify PR deploy preview.
    // Never accept an arbitrary Host header as a scan target.
    const requestHostname = new URL(request.url).hostname.toLowerCase();
    const isPlatformProduction = requestHostname === PLATFORM_HOST;
    const isPlatformPreview = /^deploy-preview-\\d+--cybersentry-ai-fouzia2510\\.netlify\\.app$/.test(requestHostname);
    if (!isPlatformProduction && !isPlatformPreview) {
      return NextResponse.json({ error: "Platform self-scan is only available on the CyberSentryAI production site and its Netlify deploy previews." }, { status: 400 });
    }

    const audit = await auditVerifiedWebsite(requestHostname);
    const saved = await supabaseUserRequest("platform_security_scans?select=id,domain,score,findings,summary,http_status,tls_protocol,created_at", accessToken, {
      method: "POST",
      headers: { Prefer: "return=representation" },
      body: JSON.stringify({
        user_id: user.id, domain: requestHostname, score: audit.score, findings: audit.findings,
        summary: audit.summary, http_status: audit.httpStatus, tls_protocol: audit.tlsProtocol,
      }),
    });
    if (!saved.ok) return NextResponse.json({ error: "Scan ran, but the report could not be saved. Apply the platform scan migration and retry." }, { status: 503 });
    const rows = await saved.json() as Array<{ id: string }>;
    return NextResponse.json({ ok: true, scan: { id: rows[0]?.id ?? null, ...audit } });
  } catch (error) {
    const message = error instanceof Error ? error.message : "The platform scan service is unavailable.";
    return NextResponse.json({ error: message }, { status: 502 });
  }
}

export async function GET() {
  const accessToken = await getAccessToken();
  if (!accessToken) return NextResponse.json({ error: "Sign in is required." }, { status: 401 });
  try {
    const user = await getAuthenticatedUser(accessToken);
    if (!user) return NextResponse.json({ error: "Your session has expired. Sign in again." }, { status: 401 });
    const response = await supabaseUserRequest("platform_security_scans?select=id,domain,score,findings,summary,http_status,tls_protocol,created_at&order=created_at.desc&limit=30", accessToken);
    if (!response.ok) return NextResponse.json({ error: "Could not load platform scan history." }, { status: 503 });
    return NextResponse.json({ ok: true, scans: await response.json() });
  } catch {
    return NextResponse.json({ error: "Platform scan history is temporarily unavailable." }, { status: 503 });
  }
}
