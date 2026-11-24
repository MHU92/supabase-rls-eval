-- Migration: RLS for public.tickets
-- Users read/create their own tickets; admins (JWT app_metadata role = 'admin') read and update all.
-- Admin check uses raw_app_meta_data (server-controlled), not user_meta_data.

begin;

-- 1. Enable RLS and reset grants (existing table has Supabase default grants).
alter table public.tickets enable row level security;

revoke all on table public.tickets from anon, authenticated;
grant select, insert, update on table public.tickets to authenticated;

-- 2. Index the columns the policies filter on.
create index if not exists tickets_user_id_idx
on public.tickets using btree (user_id);

-- 3. Policies: one per operation, all scoped to authenticated.

-- Users read their own tickets; admins read all.
create policy "Users and admins can read tickets"
on public.tickets for select
to authenticated
using (
  (select auth.uid()) = user_id
  or (select auth.jwt()) -> 'app_metadata' ->> 'role' = 'admin'
);

-- Users create tickets only for themselves.
create policy "Users can create their own tickets"
on public.tickets for insert
to authenticated
with check ( (select auth.uid()) = user_id );

-- Admins update any ticket. Ownership is not a condition for update.
create policy "Admins can update tickets"
on public.tickets for update
to authenticated
using ( (select auth.jwt()) -> 'app_metadata' ->> 'role' = 'admin' )
with check ( (select auth.jwt()) -> 'app_metadata' ->> 'role' = 'admin' );

commit;
