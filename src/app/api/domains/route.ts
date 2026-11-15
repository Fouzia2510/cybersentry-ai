import { createHmac } from "node:crypto";
import { NextResponse } from "next/server";
import { validatePublicDomain } from "@/lib/security/domain-validation";
import { getAccessToken, getAuthenticatedUser, supabaseUserRequest } from "@/lib/supabase-rest";

const CHALLENGE_TTL_SECONDS = 30 * 60;

export async function POST(request: Request) {
  const accessToken = await getAccessToken();
  if (!accessToken) return NextResponse.json({ error: "Sign in is required." }, { status: 401 });
  try {
    const user = await getAuthenticatedUser(accessToken);
    if (!user) return NextResponse.json({ error: "Your session has expired. Sign in again." }, { status: 401 });

    let body: unknown;
    try { body = await request.json(); } catch {
      return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
    }
    const input = typeof body === "object" && body !== null && "domain" in body ? (body as {domain?: unknown}).domain : undefined;
    const validated = validatePublicDomain(input);
    if (!validated.ok) return NextResponse.json(validated, { status: 400 });

    const lookup = await supabaseUserRequest(
      `domains?domain=eq.${encodeURIComponent(validated.hostname)}&select=id,verification_status&limit=1`,
      accessToken,
    );
    if (!lookup.ok) return NextResponse.json({ error: "Could not check domain record. Apply the database migration and confirm RLS." }, { status: 503 });
    const rows = await lookup.json() as Array<{id:string; verification_status:string}>;
    if (rows[0]?.verification_status === "verified") {
      return NextResponse.json({ error: "This domain is already verified in your workspace." }, { status: 409 });
    }

    if (!rows.length) {
      const insert = await supabaseUserRequest("domains", accessToken, {
        method: "POST",
        headers: { Prefer: "return=minimal" },
        body: JSON.stringify({ user_id: user.id, domain: validated.hostname, verification_status: "pending" }),
      });
      if (!insert.ok) return NextResponse.json({ error: "Could not save the pending domain. Check the database migration and RLS policies." }, { status: 503 });
    }

    const secret = process.env.DOMAIN_VERIFICATION_SECRET;
    if (!secret || secret.length < 32) {
      return NextResponse.json({ error: "DOMAIN_VERIFICATION_SECRET must be configured with at least 32 characters." }, { status: 503 });
    }
    const expires = Math.floor(Date.now() / 1000) + CHALLENGE_TTL_SECONDS;
    const signature = createHmac("sha256", secret).update(`cybersentryai:v1:${validated.hostname}:${expires}`).digest("hex");
    return NextResponse.json({
      ok: true,
      domain: validated.hostname,
      status: "verification_pending",
      recordType: "TXT",
      recordName: `_cybersentryai.${validated.hostname}`,
      recordValue: `${expires}.${signature}`,
      expiresAt: new Date(expires * 1000).toISOString(),
      message: "Add this DNS TXT record, then request verification. No website scan has been started.",
    });
  } catch {
    return NextResponse.json({ error: "Supabase configuration or request failed." }, { status: 503 });
  }
}
