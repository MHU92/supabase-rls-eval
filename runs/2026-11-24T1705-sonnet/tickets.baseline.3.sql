-- Enable RLS and lock down the default grants
alter table public.tickets enable row level security;

revoke all on public.tickets from anon;
revoke all on public.tickets from authenticated;

grant select, insert, update on public.tickets to authenticated;

-- Users can read their own tickets
create policy "Users can read own tickets"
  on public.tickets
  for select
  to authenticated
  using (user_id = (select auth.uid()));

-- Users can create tickets for themselves only
create policy "Users can create own tickets"
  on public.tickets
  for insert
  to authenticated
  with check (user_id = (select auth.uid()));

-- Admins can read every ticket.
-- Uses app_metadata (server-controlled), NOT user_metadata, which users can edit themselves.
create policy "Admins can read all tickets"
  on public.tickets
  for select
  to authenticated
  using (((select auth.jwt()) -> 'app_metadata' ->> 'role') = 'admin');

-- Admins can update every ticket
create policy "Admins can update all tickets"
  on public.tickets
  for update
  to authenticated
  using (((select auth.jwt()) -> 'app_metadata' ->> 'role') = 'admin')
  with check (((select auth.jwt()) -> 'app_metadata' ->> 'role') = 'admin');
