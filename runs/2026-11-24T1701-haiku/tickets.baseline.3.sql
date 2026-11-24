-- Support ticket access control.
-- Admin role is read from app_metadata, not user_metadata: users can change
-- user_metadata themselves via supabase.auth.updateUser(), but only the
-- backend (service role) can write app_metadata.

alter table public.tickets enable row level security;

-- Remove Supabase's default broad grants; RLS policies below then control access.
revoke all on public.tickets from anon;
revoke all on public.tickets from authenticated;
grant select, insert, update on public.tickets to authenticated;

create index if not exists tickets_user_id_idx on public.tickets (user_id);

drop policy if exists "tickets_select_own_or_admin" on public.tickets;
create policy "tickets_select_own_or_admin"
  on public.tickets
  for select
  to authenticated
  using (
    user_id = (select auth.uid())
    or (select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin'
  );

drop policy if exists "tickets_insert_own" on public.tickets;
create policy "tickets_insert_own"
  on public.tickets
  for insert
  to authenticated
  with check (
    user_id = (select auth.uid())
  );

drop policy if exists "tickets_update_admin" on public.tickets;
create policy "tickets_update_admin"
  on public.tickets
  for update
  to authenticated
  using (
    (select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin'
  )
  with check (
    (select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin'
  );
