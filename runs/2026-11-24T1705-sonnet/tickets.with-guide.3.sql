-- Enable RLS and lock down grants
alter table public.tickets enable row level security;

revoke all on table public.tickets from anon, authenticated;

-- Users: read + create. Admins: read + update.
grant select, insert, update on table public.tickets to authenticated;

-- Index for the policy filter column
create index if not exists tickets_user_id_idx
on public.tickets
using btree (user_id);

-- SELECT: owners read their own tickets, admins read all.
-- Role is read from app_metadata (not user-editable), never user_metadata.
create policy "Users read own tickets, admins read all"
on public.tickets for select
to authenticated
using (
  (select auth.uid()) = user_id
  or (select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin'
);

-- INSERT: users can only create tickets for themselves.
create policy "Users create their own tickets"
on public.tickets for insert
to authenticated
with check (
  (select auth.uid()) = user_id
);

-- UPDATE: admins only.
create policy "Admins update all tickets"
on public.tickets for update
to authenticated
using (
  (select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin'
)
with check (
  (select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin'
);
