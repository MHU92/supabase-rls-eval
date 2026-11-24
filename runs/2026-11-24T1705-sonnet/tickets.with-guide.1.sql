-- Enable RLS and lock down grants
alter table public.tickets enable row level security;

revoke all on table public.tickets from anon, authenticated;

-- Users: select + insert (own tickets). Admins: select + update (all tickets).
grant select, insert, update on table public.tickets to authenticated;

-- Index the column used by the policies
create index if not exists tickets_user_id_idx
on public.tickets using btree (user_id);

-- SELECT: users read their own tickets; admins read all.
-- Role is read from app_metadata (not user_metadata, which users can edit).
create policy "Users can view their own tickets, admins can view all."
on public.tickets for select
to authenticated
using (
  (select auth.uid()) = user_id
  or (select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin'
);

-- INSERT: users create tickets only for themselves.
create policy "Users can create their own tickets."
on public.tickets for insert
to authenticated
with check ( (select auth.uid()) = user_id );

-- UPDATE: admins only, on any ticket.
create policy "Admins can update all tickets."
on public.tickets for update
to authenticated
using ( (select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin' )
with check ( (select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin' );
