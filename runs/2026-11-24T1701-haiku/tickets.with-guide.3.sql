-- Migration: Row Level Security for public.tickets
begin;

alter table public.tickets enable row level security;

-- Remove the default grants. Only signed-in users get access, and deletes are not exposed.
revoke all on table public.tickets from anon, authenticated;
grant select, insert, update on table public.tickets to authenticated;

-- Policies filter on user_id, so index it.
create index if not exists tickets_user_id_idx
on public.tickets using btree (user_id);

-- Admin role is read from app_metadata, which end users cannot modify.
-- user_metadata is editable by the user and must not drive authorization.

create policy "Users can read their own tickets"
on public.tickets for select
to authenticated
using ( (select auth.uid()) = user_id );

create policy "Admins can read all tickets"
on public.tickets for select
to authenticated
using ( ((select auth.jwt()) -> 'app_metadata' ->> 'role') = 'admin' );

create policy "Users can create their own tickets"
on public.tickets for insert
to authenticated
with check ( (select auth.uid()) = user_id );

create policy "Admins can update all tickets"
on public.tickets for update
to authenticated
using ( ((select auth.jwt()) -> 'app_metadata' ->> 'role') = 'admin' )
with check ( ((select auth.jwt()) -> 'app_metadata' ->> 'role') = 'admin' );

commit;
