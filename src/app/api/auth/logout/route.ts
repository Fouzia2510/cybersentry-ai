import { NextResponse } from "next/server";
import {
  clearSessionCookies,
  getAccessToken,
  getSupabaseConfig,
  isSameOriginRequest,
} from "@/lib/supabase-rest";

export async function POST(request: Request) {
  if (!isSameOriginRequest(request)) {
    return NextResponse.json({ error: "Cross-origin request rejected." }, { status: 403 });
  }

  let logoutConfirmed = false;
  try {
    const accessToken = await getAccessToken();
    if (accessToken) {
      const { url, key } = getSupabaseConfig();
      const response = await fetch(`${url}/auth/v1/logout?scope=global`, {
        method: "POST",
        headers: {
          apikey: key,
          Authorization: `Bearer ${accessToken}`,
        },
        cache: "no-store",
      });
      logoutConfirmed = response.ok;
    } else {
      logoutConfirmed = true;
    }
  } catch {
    logoutConfirmed = false;
  }

  const response = NextResponse.json(
    logoutConfirmed
      ? { ok: true }
      : { ok: false, error: "Local cookies were cleared, but Supabase could not confirm session revocation." },
    { status: logoutConfirmed ? 200 : 502 },
  );
  clearSessionCookies(response);
  return response;
}
