-- Allow platform self-scans to store their own deploy-preview hostnames.
-- Keep the scan target restricted to this Netlify site and its numbered previews.

alter table public.platform_security_scans
  drop constraint if exists platform_security_scans_domain_check;

alter table public.platform_security_scans
  add constraint platform_security_scans_domain_check
  check (
    domain = 'cybersentry-ai-fouzia2510.netlify.app'
    or domain ~ '^deploy-preview-[0-9]+--cybersentry-ai-fouzia2510[.]netlify[.]app$'
  );

drop policy if exists "Users can create their own platform scans" on public.platform_security_scans;
create policy "Users can create their own platform scans"
  on public.platform_security_scans for insert to authenticated
  with check (
    user_id = (select auth.uid())
    and (
      domain = 'cybersentry-ai-fouzia2510.netlify.app'
      or domain ~ '^deploy-preview-[0-9]+--cybersentry-ai-fouzia2510[.]netlify[.]app$'
    )
  );
