import { NextResponse } from "next/server";
import { getSupabaseConfig, sessionCookies } from "@/lib/supabase-rest";

export async function POST(request: Request) {
  let body: unknown;
  try { body = await request.json(); } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }
  const email = typeof body === "object" && body !== null && "email" in body ? (body as {email?: unknown}).email : null;
  const password = typeof body === "object" && body !== null && "password" in body ? (body as {password?: unknown}).password : null;
  if (typeof email !== "string" || typeof password !== "string" || !email.trim() || password.length < 8 || password.length > 256) {
    return NextResponse.json({ error: "Enter a valid email and password (at least 8 characters)." }, { status: 400 });
  }

  try {
    const { url, key } = getSupabaseConfig();
    const auth = await fetch(`${url}/auth/v1/token?grant_type=password`, {
      method: "POST",
      headers: { apikey: key, "Content-Type": "application/json" },
      body: JSON.stringify({ email: email.trim(), password }),
      cache: "no-store",
    });
    const result = await auth.json();
    if (!auth.ok || !result.access_token || !result.refresh_token) {
      return NextResponse.json({ error: "Sign-in failed. Check your email and password." }, { status: 401 });
    }
    const response = NextResponse.json({ ok: true, user: { email: result.user?.email } });
    const secure = process.env.NODE_ENV === "production";
    response.cookies.set(sessionCookies.access, result.access_token, { httpOnly: true, secure, sameSite: "lax", path: "/", maxAge: Math.min(result.expires_in ?? 3600, 3600) });
    response.cookies.set(sessionCookies.refresh, result.refresh_token, { httpOnly: true, secure, sameSite: "lax", path: "/", maxAge: 60 * 60 * 24 * 30 });
    return response;
  } catch {
    return NextResponse.json({ error: "Supabase is not configured. Add the required environment variables." }, { status: 503 });
  }
}
