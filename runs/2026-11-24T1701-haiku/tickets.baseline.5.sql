-- Row Level Security for public.tickets
--
-- Admin check reads role from app_metadata, not user_metadata. Authenticated
-- users can edit their own user_metadata via supabase.auth.updateUser(), so a
-- role stored there would let any user grant themselves admin. app_metadata is
-- writable only with the service role. If your backend writes role to
-- user_metadata, change the admin checks below, but that exposes every ticket
-- to privilege escalation.

-- Remove Supabase's default broad grants. Access is limited to what the rule allows.
revoke all on public.tickets from anon;
revoke all on public.tickets from authenticated;

-- Users need to read and create tickets. Updates are admin-only, enforced by RLS.
-- No DELETE grant is given.
grant select, insert, update on public.tickets to authenticated;

alter table public.tickets enable row level security;

-- Users can read their own tickets.
create policy tickets_select_own
  on public.tickets
  for select
  to authenticated
  using (user_id = (select auth.uid()));

-- Admins can read every ticket.
create policy tickets_select_admin
  on public.tickets
  for select
  to authenticated
  using (coalesce((select auth.jwt()) -> 'app_metadata' ->> 'role', '') = 'admin');

-- Users can create tickets only for themselves.
create policy tickets_insert_own
  on public.tickets
  for insert
  to authenticated
  with check (user_id = (select auth.uid()));

-- Admins can update any ticket. The check also stops them from moving a ticket to another user.
create policy tickets_update_admin
  on public.tickets
  for update
  to authenticated
  using (coalesce((select auth.jwt()) -> 'app_metadata' ->> 'role', '') = 'admin')
  with check (coalesce((select auth.jwt()) -> 'app_metadata' ->> 'role', '') = 'admin');
