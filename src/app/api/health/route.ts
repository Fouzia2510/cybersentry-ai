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
          supabase: { status: "unreachable" },
        },
        { headers: noStoreHeaders },
      );
    }

    const response = await fetch(new URL("/rest/v1/", baseUrl), {
      method: "GET",
      headers: {
        apikey: supabaseKey,
        Authorization: `Bearer ${supabaseKey}`,
      },
      cache: "no-store",
      signal: AbortSignal.timeout(5000),
    });

    return NextResponse.json(
      {
        ok: true,
        checkedAt: new Date().toISOString(),
        supabase: { status: response.ok ? "reachable" : "unreachable" },
      },
      { headers: noStoreHeaders },
    );
  } catch {
    return NextResponse.json(
      {
        ok: true,
        checkedAt: new Date().toISOString(),
        supabase: { status: "unreachable" },
      },
      { headers: noStoreHeaders },
    );
  }
}
