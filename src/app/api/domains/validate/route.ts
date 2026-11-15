import { NextResponse } from "next/server";
import { validatePublicDomain } from "@/lib/security/domain-validation";

export const runtime = "nodejs";

export async function POST(request: Request) {
  let body: unknown;

  try {
    body = await request.json();
  } catch {
    return NextResponse.json(
      { ok: false, error: "Request body must be valid JSON." },
      { status: 400 },
    );
  }

  const domain =
    typeof body === "object" && body !== null && "domain" in body
      ? (body as { domain?: unknown }).domain
      : undefined;

  const result = validatePublicDomain(domain);
  if (!result.ok) {
    return NextResponse.json(result, { status: 400 });
  }

  return NextResponse.json({
    ok: true,
    domain: result.hostname,
    normalizedUrl: result.normalizedUrl,
    status: "validation_only",
    message:
      "Domain format accepted. It has not been saved, ownership-verified, or scanned.",
  });
}
