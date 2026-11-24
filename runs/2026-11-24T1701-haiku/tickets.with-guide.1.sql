-- Migration: ticket access under RLS
-- Users read and create their own tickets; admins (JWT app_metadata role = 'admin') read and update all tickets.
-- Note: the brief says the backend sets role in the user's Auth metadata. raw_app_meta_data is the server-only
-- field and is the correct place for authorization data; raw_user_meta_data is user-editable and must not be trusted.

begin;

-- 1. Enable RLS and set grants: revoke default privileges, grant back only what the app needs.
alter table public.tickets enable row level security;

revoke all on table public.tickets from anon, authenticated;
grant select, insert, update on table public.tickets to authenticated;
-- No delete grant: the access rule does not mention deletion.

-- 2. Index the columns the policies filter on.
create index if not exists tickets_user_id_idx on public.tickets using btree (user_id);

-- 3. Policies, one per operation, all scoped to authenticated.

-- Admin check: reads the signed-in caller's JWT claim. Cheap, no table reads, no recursion.
-- Wrapped in (select ...) in the policies so Postgres caches it per statement.

create policy "Users can view their own tickets"
on public.tickets for select
to authenticated
using (
  (select auth.uid()) = user_id
  or coalesce((select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin', false)
);

create policy "Users can create their own tickets"
on public.tickets for insert
to authenticated
with check ( (select auth.uid()) = user_id );

create policy "Admins can update any ticket"
on public.tickets for update
to authenticated
using ( coalesce((select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin', false) )
with check ( coalesce((select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin', false) );

commit;
