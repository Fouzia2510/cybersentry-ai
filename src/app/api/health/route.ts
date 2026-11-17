import { NextResponse } from "next/server";

const noStoreHeaders = {
  "Cache-Control": "no-store, max-age=0",
};

export async function GET() {
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const supabaseKey = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;

  if (!supabaseUrl || !supabaseKey) {
    return NextResponse.json(
      {
        ok: true,
        checkedAt: new Date().toISOString(),
        supabase: { status: "not_configured" },
      },
      { headers: noStoreHeaders },
    );
  }

  try {
    const baseUrl = new URL(supabaseUrl);
    if (baseUrl.protocol !== "https:") {
      return NextResponse.json(
        {
          ok: true,
          checkedAt: new Date().toISOString(),
          supabase: { status: "invalid_url_protocol" },
        },
        { headers: noStoreHeaders },
      );
    }

    // Probe the same Supabase Auth service used by sign-in.
    const response = await fetch(new URL("/auth/v1/health", baseUrl), {
      method: "GET",
      headers: { apikey: supabaseKey },
      cache: "no-store",
      signal: AbortSignal.timeout(8000),
    });

    return NextResponse.json(
      {
        ok: true,
        checkedAt: new Date().toISOString(),
        supabase: response.ok
          ? { status: "reachable" }
          : { status: "auth_http_error", httpStatus: response.status },
      },
      { headers: noStoreHeaders },
    );
  } catch (error) {
    const errorName = error instanceof Error ? error.name : "UnknownError";
    const cause = error instanceof Error ? error.cause : undefined;
    const causeCode =
      typeof cause === "object" && cause !== null && "code" in cause &&
      typeof cause.code === "string" && /^[A-Z0-9_]+$/.test(cause.code)
        ? cause.code
        : undefined;

    return NextResponse.json(
      {
        ok: true,
        checkedAt: new Date().toISOString(),
        supabase: {
          status: errorName === "TimeoutError" ? "timeout" : "connection_error",
          errorName,
          ...(causeCode ? { causeCode } : {}),
        },
      },
      { headers: noStoreHeaders },
    );
  }
}
