-- Migration: RLS for public.tickets
-- Users read and create their own tickets. Admins (role = 'admin' in the
-- Auth JWT app_metadata) read and update all tickets.
-- Note: the admin check reads raw_app_meta_data (server-controlled), NOT
-- raw_user_meta_data (user-editable). Backend must set role under app_metadata.

-- 1. Enable RLS and revoke default grants from client roles
alter table public.tickets enable row level security;
revoke all on table public.tickets from anon, authenticated;

-- 2. Grant back only what the app needs
--    Users: select + insert (own tickets). Admins: select + update (via same role).
grant select, insert, update on table public.tickets to authenticated;

-- 3. Index the columns the policies filter on
create index if not exists tickets_user_id_idx on public.tickets using btree (user_id);

-- 4. Policies, one per operation

create policy "Users can read their own tickets"
on public.tickets for select
to authenticated
using (
  (select auth.uid()) = user_id
  or coalesce((select auth.jwt()) -> 'app_metadata' ->> 'role', '') = 'admin'
);

create policy "Users can create their own tickets"
on public.tickets for insert
to authenticated
with check ( (select auth.uid()) = user_id );

create policy "Admins can update any ticket"
on public.tickets for update
to authenticated
using ( coalesce((select auth.jwt()) -> 'app_metadata' ->> 'role', '') = 'admin' )
with check ( coalesce((select auth.jwt()) -> 'app_metadata' ->> 'role', '') = 'admin' );
