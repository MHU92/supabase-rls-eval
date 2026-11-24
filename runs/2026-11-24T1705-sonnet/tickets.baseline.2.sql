-- Enable RLS and force it for the table owner as well
alter table public.tickets enable row level security;
alter table public.tickets force row level security;

-- Tighten the default grants: anon gets nothing, authenticated gets only what the rule needs
revoke all on table public.tickets from anon;
revoke all on table public.tickets from authenticated;
grant select, insert, update on table public.tickets to authenticated;

-- Users can read their own tickets
create policy "tickets_select_own"
on public.tickets
for select
to authenticated
using (user_id = (select auth.uid()));

-- Users can create tickets only for themselves
create policy "tickets_insert_own"
on public.tickets
for insert
to authenticated
with check (user_id = (select auth.uid()));

-- Admins can read every ticket.
-- The role is read from app_metadata (only writable by the backend / service role),
-- never from user_metadata, which users can edit themselves.
create policy "tickets_select_admin"
on public.tickets
for select
to authenticated
using (((select auth.jwt()) -> 'app_metadata' ->> 'role') = 'admin');

-- Admins can update every ticket
create policy "tickets_update_admin"
on public.tickets
for update
to authenticated
using (((select auth.jwt()) -> 'app_metadata' ->> 'role') = 'admin')
with check (((select auth.jwt()) -> 'app_metadata' ->> 'role') = 'admin');

-- Index to support the user_id policy checks
create index if not exists tickets_user_id_idx on public.tickets (user_id);
