import { NextResponse } from "next/server";
import { validatePublicDomain } from "@/lib/security/domain-validation";
import { auditVerifiedWebsite } from "@/lib/security/site-audit";
import {
  getAccessToken,
  getAuthenticatedUser,
  isSameOriginRequest,
  supabaseUserRequest,
} from "@/lib/supabase-rest";

type DomainRecord = { id: string; verification_status: string };

export async function POST(request: Request) {
  if (!isSameOriginRequest(request)) {
    return NextResponse.json({ error: "Cross-origin request rejected." }, { status: 403 });
  }

  const accessToken = await getAccessToken();
  if (!accessToken) return NextResponse.json({ error: "Sign in is required." }, { status: 401 });

  try {
    const user = await getAuthenticatedUser(accessToken);
    if (!user) return NextResponse.json({ error: "Your session has expired. Sign in again." }, { status: 401 });

    let body: unknown;
    try { body = await request.json(); } catch {
      return NextResponse.json({ error: "Request body must be valid JSON." }, { status: 400 });
    }
    const input = typeof body === "object" && body !== null && "domain" in body
      ? (body as { domain?: unknown }).domain
      : undefined;
    const validated = validatePublicDomain(input);
    if (!validated.ok) return NextResponse.json(validated, { status: 400 });

    const domainResponse = await supabaseUserRequest(
      `domains?domain=eq.${encodeURIComponent(validated.hostname)}&select=id,verification_status&limit=1`,
      accessToken,
    );
    if (!domainResponse.ok) return NextResponse.json({ error: "Could not confirm domain ownership. Refresh your domain list and try again." }, { status: 503 });
    const domains = await domainResponse.json() as DomainRecord[];
    const domain = domains[0];
    if (!domain || domain.verification_status !== "verified") {
      return NextResponse.json({ error: "Only domains with verified DNS ownership can be scanned. Verify this domain in Domain Management first." }, { status: 403 });
    }

    let audit;
    try {
      audit = await auditVerifiedWebsite(validated.hostname);
    } catch (error) {
      const message = error instanceof Error ? error.message : "The website could not be reached safely.";
      return NextResponse.json({ error: message }, { status: 502 });
    }

    const saved = await supabaseUserRequest("security_scans?select=id,domain,score,findings,summary,http_status,tls_protocol,created_at", accessToken, {
      method: "POST",
      headers: { Prefer: "return=representation" },
      body: JSON.stringify({
        user_id: user.id,
        domain_id: domain.id,
        domain: audit.domain,
        score: audit.score,
        status: "completed",
        findings: audit.findings,
        summary: audit.summary,
        http_status: audit.httpStatus,
        tls_protocol: audit.tlsProtocol,
      }),
    });
    if (!saved.ok) {
      return NextResponse.json({ error: "The scan completed, but its report could not be saved. Apply the security scan database migration and try again." }, { status: 503 });
    }
    const rows = await saved.json() as Array<{ id: string }>;
    return NextResponse.json({ ok: true, scan: { id: rows[0]?.id ?? null, ...audit } });
  } catch {
    return NextResponse.json({ error: "The security scan service is temporarily unavailable." }, { status: 503 });
  }
}

export async function GET() {
  const accessToken = await getAccessToken();
  if (!accessToken) return NextResponse.json({ error: "Sign in is required." }, { status: 401 });
  try {
    const user = await getAuthenticatedUser(accessToken);
    if (!user) return NextResponse.json({ error: "Your session has expired. Sign in again." }, { status: 401 });
    const response = await supabaseUserRequest(
      "security_scans?select=id,domain,score,status,findings,summary,http_status,tls_protocol,created_at&order=created_at.desc&limit=50",
      accessToken,
    );
    if (!response.ok) return NextResponse.json({ error: "Could not load scan history. Apply the security scan database migration first." }, { status: 503 });
    return NextResponse.json({ ok: true, scans: await response.json() });
  } catch {
    return NextResponse.json({ error: "The scan history service is temporarily unavailable." }, { status: 503 });
  }
}
