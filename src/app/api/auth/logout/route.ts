import { NextResponse } from "next/server";
import { sessionCookies } from "@/lib/supabase-rest";

export async function POST() {
  const response = NextResponse.json({ ok: true });
  for (const name of [sessionCookies.access, sessionCookies.refresh]) {
    response.cookies.set(name, "", { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "lax", path: "/", maxAge: 0 });
  }
  return response;
}
