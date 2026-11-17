import { createHmac, timingSafeEqual } from "node:crypto";
import { resolveTxt } from "node:dns/promises";
import { NextResponse } from "next/server";
import { validatePublicDomain } from "@/lib/security/domain-validation";
import {
  getAccessToken,
  getAuthenticatedUser,
  isSameOriginRequest,
  supabaseUserRequest,
} from "@/lib/supabase-rest";

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
      return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
    }
    const input = typeof body === "object" && body !== null && "domain" in body ? (body as {domain?: unknown}).domain : undefined;
    const token = typeof body === "object" && body !== null && "token" in body ? (body as {token?: unknown}).token : undefined;
    const validated = validatePublicDomain(input);
    if (!validated.ok) return NextResponse.json(validated, { status: 400 });
    if (typeof token !== "string" || token.length > 256 || !/^\d+\.[a-f0-9]{64}$/.test(token)) {
      return NextResponse.json({ error: "Verification token is invalid." }, { status: 400 });
    }

    const lookup = await supabaseUserRequest(
      `domains?domain=eq.${encodeURIComponent(validated.hostname)}&select=id,verification_status&limit=1`,
      accessToken,
    );
    if (!lookup.ok) return NextResponse.json({ error: "Could not load your domain record." }, { status: 503 });
    const rows = await lookup.json() as Array<{id:string; verification_status:string}>;
    if (!rows.length || rows[0].verification_status !== "pending") {
      return NextResponse.json({ error: "No pending domain verification was found in your workspace." }, { status: 404 });
    }

    const [expiresText, supplied] = token.split(".");
    const expires = Number(expiresText);
    if (!Number.isSafeInteger(expires) || expires <= Math.floor(Date.now() / 1000)) {
      return NextResponse.json({ error: "Verification token expired. Generate a new DNS challenge." }, { status: 400 });
    }
    const secret = process.env.DOMAIN_VERIFICATION_SECRET;
    if (!secret || secret.length < 32) return NextResponse.json({ error: "Verification service is not configured." }, { status: 503 });
    const expected = createHmac("sha256", secret).update(`cybersentryai:v1:${validated.hostname}:${expires}`).digest("hex");
    const expectedBuffer = Buffer.from(expected, "hex");
    const suppliedBuffer = Buffer.from(supplied, "hex");
    if (expectedBuffer.length !== suppliedBuffer.length || !timingSafeEqual(expectedBuffer, suppliedBuffer)) {
      return NextResponse.json({ error: "Verification token is invalid." }, { status: 400 });
    }

    let records: string[][];
    try { records = await resolveTxt(`_cybersentryai.${validated.hostname}`); } catch {
      return NextResponse.json({ error: "DNS TXT record was not found yet. Add the record and try again." }, { status: 409 });
    }
    if (!records.some((record) => record.join("") === token)) {
      return NextResponse.json({ error: "DNS TXT value does not match. Check the record and try again." }, { status: 409 });
    }

    const verified = await supabaseUserRequest("rpc/mark_domain_verified", accessToken, {
      method: "POST",
      body: JSON.stringify({ p_domain: validated.hostname }),
    });
    if (!verified.ok) return NextResponse.json({ error: "DNS matched, but the database could not save verification. Check mark_domain_verified and RLS." }, { status: 503 });
    const result = await verified.json();
    if (!result || (Array.isArray(result) && result.length === 0)) {
      return NextResponse.json({ error: "Domain verification could not be persisted for this account." }, { status: 409 });
    }
    return NextResponse.json({ ok: true, domain: validated.hostname, status: "verified", message: "Domain ownership verified. You can now run passive HTTPS security checks from Website Scanner." });
  } catch {
    return NextResponse.json({ error: "DNS verification service failed. Please retry." }, { status: 503 });
  }
}
