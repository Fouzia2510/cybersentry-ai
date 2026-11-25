import { NextResponse } from "next/server";
import { getAccessToken, getAuthenticatedUser } from "@/lib/supabase-rest";

export async function GET() {
  try {
    const accessToken = await getAccessToken();
    if (!accessToken) {
      return NextResponse.json({ authenticated: false }, { status: 401 });
    }

    const user = await getAuthenticatedUser(accessToken);
    if (!user) {
      return NextResponse.json({ authenticated: false }, { status: 401 });
    }

    return NextResponse.json({
      authenticated: true,
      user: { id: user.id, email: user.email ?? null },
    });
  } catch {
    return NextResponse.json(
      { authenticated: false, error: "Authentication service is unavailable." },
      { status: 503 },
    );
  }
}
