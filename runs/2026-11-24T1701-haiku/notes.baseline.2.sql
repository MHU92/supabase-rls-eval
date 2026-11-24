-- Enable RLS and restrict notes to their owner.
-- Signed-out visitors (anon role) get no access; signed-in users (authenticated role)
-- can only touch rows where user_id matches their own auth.uid().

alter table public.notes enable row level security;
alter table public.notes force row level security;

-- Remove Supabase's default broad grants so only the policies below apply.
revoke all on table public.notes from anon;
revoke all on table public.notes from authenticated;

-- Only signed-in users get table privileges; RLS filters rows further.
grant select, insert, update, delete on table public.notes to authenticated;

drop policy if exists "notes_select_own" on public.notes;
drop policy if exists "notes_insert_own" on public.notes;
drop policy if exists "notes_update_own" on public.notes;
drop policy if exists "notes_delete_own" on public.notes;

create policy "notes_select_own"
  on public.notes
  for select
  to authenticated
  using ((select auth.uid()) = user_id);

create policy "notes_insert_own"
  on public.notes
  for insert
  to authenticated
  with check ((select auth.uid()) = user_id);

create policy "notes_update_own"
  on public.notes
  for update
  to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);

create policy "notes_delete_own"
  on public.notes
  for delete
  to authenticated
  using ((select auth.uid()) = user_id);
