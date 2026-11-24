-- Enable RLS (also applies to table owner via FORCE)
alter table public.tickets enable row level security;
alter table public.tickets force row level security;

-- Tighten Supabase's default grants: no anonymous access, no delete,
-- and only the privileges the access rule needs for signed-in users.
revoke all on table public.tickets from anon;
revoke all on table public.tickets from authenticated;
grant select, insert, update on table public.tickets to authenticated;

-- Users can read their own tickets.
create policy "tickets_select_own"
  on public.tickets
  for select
  to authenticated
  using (user_id = (select auth.uid()));

-- Users can create tickets only for themselves.
create policy "tickets_insert_own"
  on public.tickets
  for insert
  to authenticated
  with check (user_id = (select auth.uid()));

-- Admins can read every ticket.
-- Uses app_metadata (only writable server-side), NOT user_metadata,
-- which end users can modify themselves.
create policy "tickets_select_admin"
  on public.tickets
  for select
  to authenticated
  using (((select auth.jwt()) -> 'app_metadata' ->> 'role') = 'admin');

-- Admins can update every ticket.
create policy "tickets_update_admin"
  on public.tickets
  for update
  to authenticated
  using (((select auth.jwt()) -> 'app_metadata' ->> 'role') = 'admin')
  with check (((select auth.jwt()) -> 'app_metadata' ->> 'role') = 'admin');
