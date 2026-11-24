-- Support tickets: RLS for users (own tickets) and admins (all tickets).
-- Admin role is read from app_metadata, which users cannot modify.
-- user_metadata is user-editable and must not be used for authorization.

alter table public.tickets enable row level security;

-- Drop the default grants for client roles. Policies alone do not remove them.
revoke all on table public.tickets from anon, authenticated;

-- Only the operations the rule needs. No delete grant: the rule does not allow it.
grant select, insert, update on table public.tickets to authenticated;

-- Index the column the select policy filters on.
create index if not exists tickets_user_id_idx
  on public.tickets using btree (user_id);

-- Users read their own tickets; admins read every ticket.
create policy "Users read own tickets, admins read all"
on public.tickets for select
to authenticated
using (
  (select auth.uid()) = user_id
  or (select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin'
);

-- Users create tickets only for themselves.
create policy "Users create own tickets"
on public.tickets for insert
to authenticated
with check ( (select auth.uid()) = user_id );

-- Only admins update tickets, and the row must still be admin-visible after the update.
create policy "Admins update all tickets"
on public.tickets for update
to authenticated
using ( (select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin' )
with check ( (select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin' );
