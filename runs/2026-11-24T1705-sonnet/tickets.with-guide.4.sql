-- Enable RLS and lock down default grants
alter table public.tickets enable row level security;

revoke all on table public.tickets from anon, authenticated;

-- Users: select + insert. Admins: select + update.
grant select, insert, update on table public.tickets to authenticated;

-- Index for policy filter column
create index if not exists tickets_user_id_idx
on public.tickets using btree (user_id);

-- SELECT: own tickets, or any ticket for admins (app_metadata is not user-editable)
create policy "Users read own tickets, admins read all"
on public.tickets for select
to authenticated
using (
  (select auth.uid()) = user_id
  or coalesce((select auth.jwt()) -> 'app_metadata' ->> 'role', '') = 'admin'
);

-- INSERT: users create tickets only for themselves
create policy "Users create own tickets"
on public.tickets for insert
to authenticated
with check ( (select auth.uid()) = user_id );

-- UPDATE: admins only
create policy "Admins update all tickets"
on public.tickets for update
to authenticated
using ( coalesce((select auth.jwt()) -> 'app_metadata' ->> 'role', '') = 'admin' )
with check ( coalesce((select auth.jwt()) -> 'app_metadata' ->> 'role', '') = 'admin' );
