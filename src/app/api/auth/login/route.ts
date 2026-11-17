import { NextResponse } from "next/server";
import {
  getSupabaseConfig,
  isSameOriginRequest,
  setSessionCookies,
} from "@/lib/supabase-rest";

export async function POST(request: Request) {
  if (!isSameOriginRequest(request)) {
    return NextResponse.json({ error: "Cross-origin request rejected." }, { status: 403 });
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }

  const email = typeof body === "object" && body !== null && "email" in body
    ? (body as { email?: unknown }).email
    : null;
  const password = typeof body === "object" && body !== null && "password" in body
    ? (body as { password?: unknown }).password
    : null;

  if (
    typeof email !== "string" ||
    typeof password !== "string" ||
    !email.trim() ||
    email.length > 254 ||
    password.length < 8 ||
    password.length > 256
  ) {
    return NextResponse.json(
      { error: "Enter a valid email and password (at least 8 characters)." },
      { status: 400 },
    );
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

    if (
      !auth.ok ||
      typeof result.access_token !== "string" ||
      typeof result.refresh_token !== "string"
    ) {
      return NextResponse.json(
        { error: "Sign-in failed. Check your email and password." },
        { status: 401 },
      );
    }

    const response = NextResponse.json({
      ok: true,
      user: { email: result.user?.email ?? email.trim() },
    });
    setSessionCookies(response, result);
    return response;
  } catch {
    return NextResponse.json(
      { error: "Supabase is not configured or could not be reached." },
      { status: 503 },
    );
  }
}
