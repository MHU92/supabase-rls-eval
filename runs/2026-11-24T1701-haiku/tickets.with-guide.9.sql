-- Support tickets: users read and create their own; admins read and update all.
-- Admin role is read from raw_app_meta_data (app_metadata), which end users cannot modify.
-- The backend must write role = 'admin' into app_metadata, not user_metadata.

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
