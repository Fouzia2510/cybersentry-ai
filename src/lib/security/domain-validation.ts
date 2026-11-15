import { isIP } from "node:net";

export type DomainValidationResult =
  | { ok: true; hostname: string; normalizedUrl: string }
  | { ok: false; error: string };

const blockedSuffixes = [
  ".localhost",
  ".local",
  ".internal",
  ".test",
  ".invalid",
  ".example",
  ".onion",
];

export function validatePublicDomain(input: unknown): DomainValidationResult {
  if (typeof input !== "string" || input.trim().length === 0) {
    return { ok: false, error: "Enter a domain name, such as example.com." };
  }

  const value = input.trim();
  if (value.length > 253 || /[\s\\\0-\x1f]/.test(value)) {
    return { ok: false, error: "The domain contains invalid characters or is too long." };
  }
  if (value.includes("*")) {
    return { ok: false, error: "Wildcard domains are not supported." };
  }

  let parsed: URL;
  try {
    parsed = new URL(/^[a-z][a-z\d+.-]*:\/\//i.test(value) ? value : `https://${value}`);
  } catch {
    return { ok: false, error: "Enter a valid domain name." };
  }

  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    return { ok: false, error: "Only HTTP and HTTPS website addresses are supported." };
  }
  if (parsed.username || parsed.password) {
    return { ok: false, error: "URLs containing usernames or passwords are not allowed." };
  }
  if (parsed.port && !((parsed.protocol === "https:" && parsed.port === "443") || (parsed.protocol === "http:" && parsed.port === "80"))) {
    return { ok: false, error: "Custom ports are not supported." };
  }
  if (parsed.pathname !== "/" || parsed.search || parsed.hash) {
    return { ok: false, error: "Enter only the domain name, without a page path, query, or fragment." };
  }

  const hostname = parsed.hostname.toLowerCase().replace(/\.$/, "");
  if (!hostname || hostname.length > 253 || isIP(hostname) !== 0 || !hostname.includes(".")) {
    return { ok: false, error: "Enter a public domain name, not an IP address or local hostname." };
  }
  if (blockedSuffixes.some((suffix) => hostname === suffix.slice(1) || hostname.endsWith(suffix))) {
    return { ok: false, error: "Local, reserved, and non-public domain suffixes are not allowed." };
  }

  const labels = hostname.split(".");
  const validLabel = /^[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?$/;
  if (
    labels.some((label) => label.length > 63 || !validLabel.test(label)) ||
    labels[labels.length - 1].length < 2
  ) {
    return { ok: false, error: "The domain name format is invalid." };
  }

  return {
    ok: true,
    hostname,
    normalizedUrl: `https://${hostname}`,
  };
}
