-- Migration: RLS for public.tickets
-- Access rule:
--   * Users can read and create their own tickets.
--   * Admins (JWT app_metadata/user metadata role = 'admin') can read and update all tickets.
-- Note: role is read from raw_app_meta_data (server-set, not user-editable).

alter table public.tickets enable row level security;

-- Remove Supabase default grants; re-grant only what the app needs.
revoke all on table public.tickets from anon, authenticated;
grant select, insert, update on table public.tickets to authenticated;

-- Index the columns the policies filter on.
create index if not exists tickets_user_id_idx
  on public.tickets using btree (user_id);

-- SELECT: owner or admin
create policy "Users can view their own tickets"
on public.tickets for select
to authenticated
using (
  (select auth.uid()) = user_id
  or (select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin'
);

-- INSERT: only for own tickets
create policy "Users can create their own tickets"
on public.tickets for insert
to authenticated
with check ( (select auth.uid()) = user_id );

-- UPDATE: admins only, for every ticket
create policy "Admins can update tickets"
on public.tickets for update
to authenticated
using ( (select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin' )
with check ( (select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin' );
