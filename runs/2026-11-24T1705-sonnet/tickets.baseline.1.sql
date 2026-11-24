alter table public.tickets enable row level security;

-- Tighten the default grants: no anonymous access, no delete.
revoke all on public.tickets from anon;
revoke all on public.tickets from authenticated;
grant select, insert, update on public.tickets to authenticated;

-- Users can read their own tickets; admins can read all tickets.
-- The role is read from app_metadata, which only the backend can set.
-- user_metadata is editable by end users and must not be used for authorization.
create policy "tickets_select_own_or_admin"
  on public.tickets
  for select
  to authenticated
  using (
    user_id = (select auth.uid())
    or ((select auth.jwt()) -> 'app_metadata' ->> 'role') = 'admin'
  );

-- Users can create tickets only for themselves.
create policy "tickets_insert_own"
  on public.tickets
  for insert
  to authenticated
  with check (
    user_id = (select auth.uid())
  );

-- Only admins can update tickets.
create policy "tickets_update_admin"
  on public.tickets
  for update
  to authenticated
  using (
    ((select auth.jwt()) -> 'app_metadata' ->> 'role') = 'admin'
  )
  with check (
    ((select auth.jwt()) -> 'app_metadata' ->> 'role') = 'admin'
  );

-- Index to support the ownership check.
create index if not exists tickets_user_id_idx on public.tickets (user_id);
