-- Prevent authenticated users from directly changing verification status.
-- The security-definer RPC remains the only path that marks a domain verified.

drop policy if exists "Users can update their own domains" on public.domains;
revoke update on public.domains from authenticated;
