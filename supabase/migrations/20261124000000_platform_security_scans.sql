create table if not exists public.platform_security_scans (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  domain text not null check (domain = 'cybersentry-ai-fouzia2510.netlify.app'),
  score integer not null check (score between 0 and 100),
  findings jsonb not null default '[]'::jsonb,
  summary jsonb not null default '{}'::jsonb,
  http_status integer,
  tls_protocol text,
  created_at timestamptz not null default now()
);

alter table public.platform_security_scans enable row level security;
drop policy if exists "Users can read their own platform scans" on public.platform_security_scans;
drop policy if exists "Users can create their own platform scans" on public.platform_security_scans;
create policy "Users can read their own platform scans"
  on public.platform_security_scans for select to authenticated
  using (user_id = (select auth.uid()));
create policy "Users can create their own platform scans"
  on public.platform_security_scans for insert to authenticated
  with check (
    user_id = (select auth.uid())
    and domain = 'cybersentry-ai-fouzia2510.netlify.app'
  );
grant select, insert on public.platform_security_scans to authenticated;
