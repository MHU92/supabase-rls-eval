-- Enable RLS and reset grants
alter table public.tickets enable row level security;

revoke all on table public.tickets from anon, authenticated;

-- Signed-in users read and create; admins also update. No delete, no anon access.
grant select, insert, update on table public.tickets to authenticated;

-- Index the column the policies filter on
create index if not exists tickets_user_id_idx
on public.tickets
using btree (user_id);

-- SELECT: users read their own tickets
create policy "Users can read their own tickets"
on public.tickets for select
to authenticated
using ( (select auth.uid()) = user_id );

-- SELECT: admins read every ticket (role from app_metadata, which users cannot edit)
create policy "Admins can read all tickets"
on public.tickets for select
to authenticated
using ( (select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin' );

-- INSERT: users create tickets only for themselves
create policy "Users can create their own tickets"
on public.tickets for insert
to authenticated
with check ( (select auth.uid()) = user_id );

-- UPDATE: admins update every ticket
create policy "Admins can update all tickets"
on public.tickets for update
to authenticated
using ( (select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin' )
with check ( (select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin' );
