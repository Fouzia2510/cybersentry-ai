-- CyberSentryAI domain ownership records.
-- Safe to apply to a fresh project; review existing public.domains columns before applying to a live database.

create table if not exists public.domains (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  domain text not null,
  verification_status text not null default 'pending'
    check (verification_status in ('pending', 'verified')),
  verified_at timestamptz,
  created_at timestamptz not null default now(),
  unique (user_id, domain)
);

alter table public.domains enable row level security;

drop policy if exists "Users can view their own domains" on public.domains;
create policy "Users can view their own domains"
  on public.domains for select to authenticated
  using ((select auth.uid()) = user_id);

drop policy if exists "Users can create their own domains" on public.domains;
create policy "Users can create their own domains"
  on public.domains for insert to authenticated
  with check ((select auth.uid()) = user_id);

drop policy if exists "Users can update their own domains" on public.domains;
create policy "Users can update their own domains"
  on public.domains for update to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);

create or replace function public.mark_domain_verified(p_domain text)
returns table (
  id uuid,
  domain text,
  verification_status text,
  verified_at timestamptz
)
language sql
security definer
set search_path = ''
as $$
  update public.domains as d
  set verification_status = 'verified',
      verified_at = now()
  where d.user_id = auth.uid()
    and d.domain = p_domain
    and d.verification_status = 'pending'
  returning d.id, d.domain, d.verification_status, d.verified_at;
$$;

revoke all on function public.mark_domain_verified(text) from public;
revoke all on function public.mark_domain_verified(text) from anon;
grant execute on function public.mark_domain_verified(text) to authenticated;

grant select, insert, update on public.domains to authenticated;
