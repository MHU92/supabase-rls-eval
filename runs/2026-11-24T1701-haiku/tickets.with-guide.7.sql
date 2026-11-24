-- Support tickets: owners read and create their own tickets, admins read and update all.
-- Admin status comes from app_metadata, which only the backend can write. user_metadata
-- is editable by the signed-in user, so it must not be used for authorization.
-- Note: tickets.id has no default, so inserts must supply an id.

alter table public.tickets enable row level security;

revoke all on table public.tickets from anon, authenticated;
grant select, insert, update on table public.tickets to authenticated;

create index if not exists tickets_user_id_idx
on public.tickets using btree (user_id);

create policy "Users and admins can read tickets"
on public.tickets for select
to authenticated
using (
  (select auth.uid()) = user_id
  or (select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin'
);

create policy "Users can create their own tickets"
on public.tickets for insert
to authenticated
with check ( (select auth.uid()) = user_id );

create policy "Admins can update any ticket"
on public.tickets for update
to authenticated
using ( (select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin' )
with check ( (select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin' );
