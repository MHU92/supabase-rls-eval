-- Enable RLS (also applies to existing data)
alter table public.tickets enable row level security;
alter table public.tickets force row level security;

-- Tighten the default grants: no anonymous access, no delete/truncate for anyone
revoke all on table public.tickets from anon;
revoke all on table public.tickets from authenticated;
grant select, insert, update on table public.tickets to authenticated;

-- Users can read their own tickets
create policy "tickets_select_own"
  on public.tickets
  for select
  to authenticated
  using (user_id = (select auth.uid()));

-- Admins can read every ticket.
-- The role is read from app_metadata, which only the backend can set.
-- user_metadata must NOT be used because users can edit it themselves.
create policy "tickets_select_admin"
  on public.tickets
  for select
  to authenticated
  using (((select auth.jwt()) -> 'app_metadata' ->> 'role') = 'admin');

-- Users can create tickets only for themselves
create policy "tickets_insert_own"
  on public.tickets
  for insert
  to authenticated
  with check (user_id = (select auth.uid()));

-- Admins can update every ticket
create policy "tickets_update_admin"
  on public.tickets
  for update
  to authenticated
  using (((select auth.jwt()) -> 'app_metadata' ->> 'role') = 'admin')
  with check (((select auth.jwt()) -> 'app_metadata' ->> 'role') = 'admin');

-- Index to support the ownership policies
create index if not exists tickets_user_id_idx on public.tickets (user_id);
