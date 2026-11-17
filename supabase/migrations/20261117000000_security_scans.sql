-- CyberSentryAI passive security scan history.
-- Run after the domain ownership migrations have been applied.

create table if not exists public.security_scans (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  domain_id uuid not null references public.domains(id) on delete cascade,
  domain text not null,
  score integer not null check (score between 0 and 100),
  status text not null default 'completed' check (status in ('completed')),
  findings jsonb not null default '[]'::jsonb,
  summary jsonb not null default '{}'::jsonb,
  http_status integer,
  tls_protocol text,
  created_at timestamptz not null default now()
);

create index if not exists security_scans_user_created_idx
  on public.security_scans (user_id, created_at desc);

create index if not exists security_scans_domain_created_idx
  on public.security_scans (domain_id, created_at desc);

alter table public.security_scans enable row level security;

drop policy if exists "Users can view their own security scans" on public.security_scans;
create policy "Users can view their own security scans"
  on public.security_scans for select to authenticated
  using ((select auth.uid()) = user_id);

drop policy if exists "Users can create scans for their verified domains" on public.security_scans;
create policy "Users can create scans for their verified domains"
  on public.security_scans for insert to authenticated
  with check (
    (select auth.uid()) = user_id
    and exists (
      select 1
      from public.domains as d
      where d.id = domain_id
        and d.user_id = (select auth.uid())
        and d.verification_status = 'verified'
    )
  );

grant select, insert on public.security_scans to authenticated;
