-- Admin role is read from app_metadata, not user_metadata. Any signed-in user can
-- change their own user_metadata via supabase.auth.updateUser(), which would let
-- anyone grant themselves admin. app_metadata can only be written server-side
-- (service role / Admin API). The backend must set app_metadata = {"role": "admin"}
-- for support staff instead of user_metadata.

-- Remove Supabase's default grants (anon/authenticated had full access).
revoke all on public.tickets from anon;
revoke all on public.tickets from authenticated;

-- Only the operations the access rule needs. No DELETE.
grant select, insert, update on public.tickets to authenticated;

alter table public.tickets enable row level security;

-- Users can read their own tickets.
create policy tickets_select_own
  on public.tickets
  for select
  to authenticated
  using (user_id = auth.uid());

-- Admins can read every ticket.
create policy tickets_select_admin
  on public.tickets
  for select
  to authenticated
  using ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');

-- Users can create tickets only for themselves.
create policy tickets_insert_own
  on public.tickets
  for insert
  to authenticated
  with check (user_id = auth.uid());

-- Admins can update every ticket.
create policy tickets_update_admin
  on public.tickets
  for update
  to authenticated
  using ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin')
  with check ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');
