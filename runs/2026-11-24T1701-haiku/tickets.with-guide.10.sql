-- Migration: RLS for public.tickets
-- Users read/create their own tickets; admins (JWT app_metadata role = 'admin' is the
-- trusted source; see note below) read and update all tickets.

alter table public.tickets enable row level security;

-- Default grants on existing projects: revoke, then grant back only what the app needs.
revoke all on table public.tickets from anon, authenticated;
grant select, insert, update on table public.tickets to authenticated;

-- Helper: true when the caller is an admin. Reads the signed JWT claim, not
-- user_metadata, because user_metadata is editable by the end user.
-- Note: the backend stores role = 'admin' in Supabase Auth metadata. For this check
-- to be safe it must be in raw_app_meta_data (app_metadata), which only the backend can write.
create or replace function private.is_admin()
returns boolean
language sql
stable
security invoker
set search_path = ''
as $$
  select coalesce((select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin', false)
$$;

create schema if not exists private;
revoke execute on function private.is_admin() from public;
grant usage on schema private to authenticated;
grant execute on function private.is_admin() to authenticated;

-- Index the filter column used by the owner policies.
create index if not exists tickets_user_id_idx on public.tickets using btree (user_id);

-- SELECT: owner or admin.
create policy "Users and admins can read tickets"
on public.tickets for select
to authenticated
using (
  (select auth.uid()) = user_id
  or (select private.is_admin())
);

-- INSERT: only for own tickets.
create policy "Users can create their own tickets"
on public.tickets for insert
to authenticated
with check ( (select auth.uid()) = user_id );

-- UPDATE: admins only. Owners are not granted update in the stated rule.
create policy "Admins can update tickets"
on public.tickets for update
to authenticated
using ( (select private.is_admin()) )
with check ( (select private.is_admin()) );
