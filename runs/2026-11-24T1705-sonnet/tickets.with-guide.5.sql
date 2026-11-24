-- Enable RLS and lock down grants
alter table public.tickets enable row level security;

revoke all on table public.tickets from anon, authenticated;
grant select, insert, update on table public.tickets to authenticated;

-- Admin check based on app_metadata (not user-editable), never user_metadata
-- Users: read own tickets
create policy "Users can read their own tickets"
on public.tickets for select
to authenticated
using ( (select auth.uid()) = user_id );

-- Admins: read all tickets
create policy "Admins can read all tickets"
on public.tickets for select
to authenticated
using ( (select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin' );

-- Users: create their own tickets
create policy "Users can create their own tickets"
on public.tickets for insert
to authenticated
with check ( (select auth.uid()) = user_id );

-- Admins: update any ticket
create policy "Admins can update all tickets"
on public.tickets for update
to authenticated
using ( (select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin' )
with check ( (select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin' );

-- Index the column used by the policies
create index tickets_user_id_idx on public.tickets using btree (user_id);
