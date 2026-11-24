-- Enable RLS. Without this, Supabase's default grants expose the table to the API roles.
alter table public.tickets enable row level security;

-- Revoke the default grants from anon. Only signed-in users should touch tickets.
revoke all on public.tickets from anon;

-- Users can read their own tickets; admins can read all tickets.
create policy tickets_select_own_or_admin
  on public.tickets
  for select
  to authenticated
  using (
    user_id = auth.uid()
    or (auth.jwt() -> 'app_metadata' ->> 'role') = 'admin'
  );

-- Users can create tickets only for themselves.
create policy tickets_insert_own
  on public.tickets
  for insert
  to authenticated
  with check (user_id = auth.uid());

-- Admins can update every ticket. Regular users get no update policy, so they cannot update.
-- The role is read from app_metadata, which only the backend (service role) can write.
-- user_metadata is writable by the user through the client SDK and must not be used for authorization.
create policy tickets_update_admin
  on public.tickets
  for update
  to authenticated
  using ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin')
  with check ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');

-- No delete policy is created, so deletes are denied for everyone except the service role, which bypasses RLS.
