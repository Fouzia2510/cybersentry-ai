import { cookies } from "next/headers";
import type { NextResponse } from "next/server";

const ACCESS_COOKIE = "sb-access-token";
const REFRESH_COOKIE = "sb-refresh-token";
const REFRESH_COOKIE_MAX_AGE = 60 * 60 * 24 * 30;

type SupabaseSession = {
  access_token: string;
  refresh_token: string;
  expires_in?: number;
};

export function getSupabaseConfig() {
  const url = "https://ktwelgkrualgvfjubzvb.supabase.co";
  const key = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;
  if (!url || !key) throw new Error("Supabase environment variables are not configured.");
  return { url, key };
}

export function isSameOriginRequest(request: Request) {
  const origin = request.headers.get("origin");
  if (!origin) return false;

  try {
    const receivedOrigin = new URL(origin);
    if (receivedOrigin.username || receivedOrigin.password) return false;

    // Netlify terminates TLS at its edge and may forward the request to the
    // Next.js runtime with an internal URL. Compare against the public host
    // and protocol supplied by the trusted hosting proxy instead.
    const forwardedHost = request.headers.get("x-forwarded-host")?.split(",")[0]?.trim();
    const host = forwardedHost || request.headers.get("host");
    const forwardedProto = request.headers.get("x-forwarded-proto")?.split(",")[0]?.trim();
    const protocol = forwardedProto
      ? `${forwardedProto.replace(/:$/, "")}:`
      : new URL(request.url).protocol;

    if (!host || !["http:", "https:"].includes(protocol)) return false;
    return receivedOrigin.host.toLowerCase() === host.toLowerCase() &&
      receivedOrigin.protocol === protocol;
  } catch {
    return false;
  }
}

export function setSessionCookies(response: NextResponse, session: SupabaseSession) {
  const secure = process.env.NODE_ENV === "production";
  const accessMaxAge = Math.max(60, Math.min(session.expires_in ?? 3600, 3600));

  response.cookies.set(ACCESS_COOKIE, session.access_token, {
    httpOnly: true,
    secure,
    sameSite: "lax",
    path: "/",
    maxAge: accessMaxAge,
  });
  response.cookies.set(REFRESH_COOKIE, session.refresh_token, {
    httpOnly: true,
    secure,
    sameSite: "lax",
    path: "/",
    maxAge: REFRESH_COOKIE_MAX_AGE,
  });
}

export function clearSessionCookies(response: NextResponse) {
  const secure = process.env.NODE_ENV === "production";
  for (const name of [ACCESS_COOKIE, REFRESH_COOKIE]) {
    response.cookies.set(name, "", {
      httpOnly: true,
      secure,
      sameSite: "lax",
      path: "/",
      maxAge: 0,
    });
  }
}

export async function getAccessToken() {
  const store = await cookies();
  const current = store.get(ACCESS_COOKIE)?.value;
  if (current) return current;

  const refreshToken = store.get(REFRESH_COOKIE)?.value;
  if (!refreshToken) return null;

  const { url, key } = getSupabaseConfig();
  let response: Response;
  try {
    response = await fetch(`${url}/auth/v1/token?grant_type=refresh_token`, {
      method: "POST",
      headers: { apikey: key, "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: refreshToken }),
      cache: "no-store",
    });
  } catch {
    return null;
  }

  if (!response.ok) {
    clearSessionCookiesOnStore(store);
    return null;
  }

  const session = (await response.json()) as Partial<SupabaseSession>;
  if (typeof session.access_token !== "string" || typeof session.refresh_token !== "string") {
    clearSessionCookiesOnStore(store);
    return null;
  }

  const secure = process.env.NODE_ENV === "production";
  store.set(ACCESS_COOKIE, session.access_token, {
    httpOnly: true,
    secure,
    sameSite: "lax",
    path: "/",
    maxAge: Math.max(60, Math.min(session.expires_in ?? 3600, 3600)),
  });
  store.set(REFRESH_COOKIE, session.refresh_token, {
    httpOnly: true,
    secure,
    sameSite: "lax",
    path: "/",
    maxAge: REFRESH_COOKIE_MAX_AGE,
  });
  return session.access_token;
}

function clearSessionCookiesOnStore(store: Awaited<ReturnType<typeof cookies>>) {
  const secure = process.env.NODE_ENV === "production";
  for (const name of [ACCESS_COOKIE, REFRESH_COOKIE]) {
    store.set(name, "", {
      httpOnly: true,
      secure,
      sameSite: "lax",
      path: "/",
      maxAge: 0,
    });
  }
}

export async function getAuthenticatedUser(accessToken: string) {
  const { url, key } = getSupabaseConfig();
  const response = await fetch(`${url}/auth/v1/user`, {
    headers: { apikey: key, Authorization: `Bearer ${accessToken}` },
    cache: "no-store",
  });
  if (!response.ok) return null;
  return (await response.json()) as { id: string; email?: string };
}

export async function supabaseUserRequest(
  path: string,
  accessToken: string,
  init: RequestInit = {},
) {
  const { url, key } = getSupabaseConfig();
  return fetch(`${url}/rest/v1/${path}`, {
    ...init,
    headers: {
      apikey: key,
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
      ...init.headers,
    },
    cache: "no-store",
  });
}

export const sessionCookies = {
  access: ACCESS_COOKIE,
  refresh: REFRESH_COOKIE,
};
