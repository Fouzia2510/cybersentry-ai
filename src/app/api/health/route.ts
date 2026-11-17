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

    // A Supabase publishable key belongs in the apikey header. It is not a
    // user access token and must not be sent as a Bearer Authorization token.
    const response = await fetch(new URL("/rest/v1/", baseUrl), {
      method: "GET",
      headers: { apikey: supabaseKey },
      cache: "no-store",
      signal: AbortSignal.timeout(5000),
    });

    return NextResponse.json(
      {
        ok: true,
        checkedAt: new Date().toISOString(),
        supabase: response.ok
          ? { status: "reachable" }
          : { status: "http_error", httpStatus: response.status },
      },
      { headers: noStoreHeaders },
    );
  } catch (error) {
    const errorName = error instanceof Error ? error.name : "UnknownError";
    return NextResponse.json(
      {
        ok: true,
        checkedAt: new Date().toISOString(),
        supabase: {
          status: errorName === "TimeoutError" ? "timeout" : "connection_error",
        },
      },
      { headers: noStoreHeaders },
    );
  }
}
