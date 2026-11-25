# CyberSentryAI Release Readiness

This checklist tracks engineering readiness. A checked item means the implementation or automated check exists; it is not a security certification.

## Current verified baseline

- [x] Pull request #2 remains isolated from `main`.
- [x] GitHub Actions lint and Next.js production build passed on commit `ec65acd`.
- [x] Netlify deploy-preview status was successful on commit `ec65acd`.
- [x] Offline rule-based report analysis; no paid AI API dependency.
- [x] Domain ownership challenge and authenticated verified-domain scan flow.
- [x] Scan history uses user-scoped Supabase access and RLS.
- [x] Platform self-scan restricts the target to CyberSentryAI Netlify hostnames.
- [x] Scanner does not follow redirects to another host.
- [x] Scanner rejects redirects and non-2xx responses rather than creating a misleading completed score.

## Release gates — still required

### Scanner reliability
- [ ] Add automated tests for public-domain validation and scanner result classification.
- [ ] Exercise DNS failure, no HTTPS listener, TLS failure, timeout, redirect, 4xx/5xx, and successful HTTPS cases.
- [ ] Add a clear distinction between DNS ownership verified and HTTPS website reachable.
- [ ] Verify that failed scans never create completed reports or update a security score.
- [ ] Review IPv4/IPv6 and DNS rebinding protections before broad public launch.

### Application security
- [ ] Review all API routes for authentication, same-origin checks, input limits, and safe error handling.
- [ ] Verify Supabase RLS policies against cross-account access attempts.
- [ ] Review session refresh and logout behaviour, including expired access tokens.
- [ ] Review rate limits and abuse controls for signup, domain challenges, and scans.
- [ ] Run dependency audit and update vulnerable packages only with compatibility checks.

### Product and operations
- [ ] Test signup, login, logout, session expiry, domain add/verify, scan, report history, and PDF export end-to-end.
- [ ] Verify dashboard health status against the configured Supabase project.
- [ ] Label passive checks, offline analysis, and unconnected threat feeds accurately.
- [ ] Add privacy policy, terms, acceptable-use policy, data retention/deletion guidance, and contact/support details.
- [ ] Add a clear service scope statement: passive configuration assessment, not penetration testing or continuous threat detection.
- [ ] Prepare production monitoring, backups, incident response, and deployment rollback steps.

### Commercial readiness
- [ ] Define free and paid plan limits only after product costs and abuse controls are understood.
- [ ] Add subscription entitlements and usage metering before advertising paid features.
- [ ] Select a payment provider available to the business owner and verify its fees/compliance.
- [ ] Do not advertise checkout, subscriptions, or revenue features until payment and entitlement flows are implemented and tested.

## Required owner actions before production

1. Confirm that each custom domain points to a real website host and has working HTTPS. A DuckDNS hostname provides DNS, not web hosting by itself.
2. Confirm the Supabase migrations listed in the repository have been applied to the intended project.
3. Review and supply the public-facing business contact, privacy, and terms information.
4. Approve production release only after all release gates are reviewed.

## Current product limitations

- Website scanning is limited to passive HTTPS homepage configuration checks.
- Offline rule-based analysis is not a hosted generative-AI service.
- Threat intelligence is derived from saved assessment findings; no external live threat feed is connected.
- Saved-report comparisons are not continuous monitoring.
- A high score only describes the controls actually checked and is not a guarantee that a site is secure.
