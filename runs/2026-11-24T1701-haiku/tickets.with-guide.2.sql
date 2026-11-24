-- Migration: RLS for public.tickets
-- Users read and create their own tickets; admins (JWT app_metadata role = 'admin') read and update all.
-- Admin role is read from raw_app_meta_data (not user-editable), never raw_user_meta_data.

begin;

-- 1. Enable RLS and reset grants to least privilege.
alter table public.tickets enable row level security;

revoke all on table public.tickets from anon, authenticated;
grant select, insert, update on table public.tickets to authenticated;

-- 2. Index the columns policies filter on.
create index if not exists tickets_user_id_idx
  on public.tickets using btree (user_id);

-- 3. Admin check. Reads app_metadata from the JWT (server-set, not user-editable).
--    Defined in a private schema so it is not exposed over the Data API.
create schema if not exists private;

create or replace function private.is_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select coalesce((select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin', false)
$$;

revoke execute on function private.is_admin() from public;
grant usage on schema private to authenticated;
grant execute on function private.is_admin() to authenticated;

-- 4. Policies, one per operation.

-- SELECT: owners read their own tickets; admins read all.
create policy "Users and admins can view tickets"
on public.tickets for select
to authenticated
using (
  (select auth.uid()) = user_id
  or (select private.is_admin())
);

-- INSERT: users may only create tickets for themselves.
create policy "Users can create their own tickets"
on public.tickets for insert
to authenticated
with check ( (select auth.uid()) = user_id );

-- UPDATE: admins only. Users have no update path.
create policy "Admins can update tickets"
on public.tickets for update
to authenticated
using ( (select private.is_admin()) )
with check ( (select private.is_admin()) );

commit;
