import { cookies } from "next/headers";

const ACCESS_COOKIE = "sb-access-token";
const REFRESH_COOKIE = "sb-refresh-token";

export function getSupabaseConfig() {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL?.replace(/\/$/, "");
  const key = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;
  if (!url || !key) throw new Error("Supabase environment variables are not configured.");
  return { url, key };
}

export async function getAccessToken() {
  const store = await cookies();
  return store.get(ACCESS_COOKIE)?.value ?? null;
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
