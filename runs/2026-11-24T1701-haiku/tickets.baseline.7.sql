begin;

-- Enable RLS so that only the policies below grant row access.
alter table public.tickets enable row level security;

-- Remove Supabase's default table grants. Only what the rule needs is granted back:
-- anon gets nothing, authenticated gets select/insert/update (no delete).
revoke all on public.tickets from anon;
revoke all on public.tickets from authenticated;
grant select, insert, update on public.tickets to authenticated;

-- Index for the ownership checks in the policies.
create index if not exists tickets_user_id_idx on public.tickets (user_id);

-- Admin role is read from app_metadata, which only the backend (service role) can write.
-- user_metadata is editable by the end user, so it must not be used for authorization.

-- Users can read their own tickets; admins can read all tickets.
create policy tickets_select_own_or_admin
  on public.tickets
  for select
  to authenticated
  using (
    user_id = (select auth.uid())
    or (select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin'
  );

-- Users can create tickets only for themselves.
create policy tickets_insert_own
  on public.tickets
  for insert
  to authenticated
  with check (user_id = (select auth.uid()));

-- Admins can update any ticket.
create policy tickets_update_admin
  on public.tickets
  for update
  to authenticated
  using ((select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin')
  with check ((select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');

commit;
