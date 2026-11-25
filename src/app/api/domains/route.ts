import { createHmac } from "node:crypto";
import { NextResponse } from "next/server";
import { validatePublicDomain } from "@/lib/security/domain-validation";
import {
  getAccessToken,
  getAuthenticatedUser,
  isSameOriginRequest,
  supabaseUserRequest,
} from "@/lib/supabase-rest";

const CHALLENGE_TTL_SECONDS = 30 * 60;

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
    const recordValue = `${expires}.${signature}`;
    // If this is a DuckDNS hostname and the token is configured, publish the TXT value
    // on the DuckDNS-managed apex hostname. Never expose the token to the client.
    if (validated.hostname.endsWith(".duckdns.org") && process.env.DUCKDNS_TOKEN) {
      const duckdns = new URL("https://www.duckdns.org/update");
      duckdns.searchParams.set("domains", validated.hostname.replace(/\.duckdns\.org$/i, ""));
      duckdns.searchParams.set("token", process.env.DUCKDNS_TOKEN);
      duckdns.searchParams.set("txt", recordValue);
      duckdns.searchParams.set("verbose", "true");
      const update = await fetch(duckdns.toString(), { cache: "no-store" });
      const updateText = (await update.text()).trim();
      if (!update.ok || !updateText.toLowerCase().startsWith("ok")) {
        return NextResponse.json({ error: "DuckDNS could not publish the TXT challenge. Check the server-side DUCKDNS_TOKEN and try again." }, { status: 502 });
      }
    }
    return NextResponse.json({
      ok: true,
      domain: validated.hostname,
      status: "verification_pending",
      recordType: "TXT",
      recordName: validated.hostname.endsWith(".duckdns.org") ? validated.hostname : `cybersentryai-verification.${validated.hostname}`,
      recordValue,
      expiresAt: new Date(expires * 1000).toISOString(),
      message: "Add this DNS TXT record, then request verification. No website scan has been started.",
    });
  } catch {
    return NextResponse.json({ error: "Supabase configuration or request failed." }, { status: 503 });
  }
}

type DomainRow = {
  id: string;
  domain: string;
  verification_status: "pending" | "verified";
  verified_at: string | null;
  created_at: string;
};

export async function GET() {
  const accessToken = await getAccessToken();
  if (!accessToken) {
    return NextResponse.json({ error: "Sign in is required." }, { status: 401 });
  }

  try {
    const user = await getAuthenticatedUser(accessToken);
    if (!user) {
      return NextResponse.json(
        { error: "Your session has expired. Sign in again." },
        { status: 401 },
      );
    }

    const response = await supabaseUserRequest(
      "domains?select=id,domain,verification_status,verified_at,created_at&order=created_at.desc",
      accessToken,
    );

    if (!response.ok) {
      return NextResponse.json(
        { error: "Could not load your domains. Check the database migration and RLS policies." },
        { status: 503 },
      );
    }

    const domains = (await response.json()) as DomainRow[];
    return NextResponse.json({
      ok: true,
      domains: domains.map((domain) => ({
        id: domain.id,
        domain: domain.domain,
        verificationStatus: domain.verification_status,
        verifiedAt: domain.verified_at,
        createdAt: domain.created_at,
      })),
    });
  } catch {
    return NextResponse.json(
      { error: "Supabase configuration or request failed." },
      { status: 503 },
    );
  }
}
