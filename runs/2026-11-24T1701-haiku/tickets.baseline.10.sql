-- Enable RLS on support tickets.
alter table public.tickets enable row level security;

-- Supabase's default grants give anon and authenticated full access.
-- Remove them, then grant only what the policies below allow.
revoke all on public.tickets from anon, authenticated;
grant select, insert, update on public.tickets to authenticated;

-- Admin check: role is read from app_metadata, not user_metadata.
-- user_metadata can be changed by the user via supabase.auth.updateUser(),
-- so a role stored there would let any user grant themselves admin.
-- The backend must write role = 'admin' to app_metadata (service role / admin API).

-- Users can read their own tickets; admins can read all tickets.
create policy tickets_select_own_or_admin
  on public.tickets
  for select
  to authenticated
  using (
    user_id = (select auth.uid())
    or coalesce(((select auth.jwt()) -> 'app_metadata' ->> 'role') = 'admin', false)
  );

-- Users can create tickets only for themselves.
create policy tickets_insert_own
  on public.tickets
  for insert
  to authenticated
  with check (
    user_id = (select auth.uid())
  );

-- Admins can update any ticket. Regular users have no update policy.
create policy tickets_update_admin
  on public.tickets
  for update
  to authenticated
  using (
    coalesce(((select auth.jwt()) -> 'app_metadata' ->> 'role') = 'admin', false)
  )
  with check (
    coalesce(((select auth.jwt()) -> 'app_metadata' ->> 'role') = 'admin', false)
  );
