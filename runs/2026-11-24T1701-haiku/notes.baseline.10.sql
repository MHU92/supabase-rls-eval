alter table public.notes enable row level security;
alter table public.notes force row level security;

revoke all on public.notes from anon;
revoke all on public.notes from public;
grant select, insert, update, delete on public.notes to authenticated;

drop policy if exists notes_select_own on public.notes;
drop policy if exists notes_insert_own on public.notes;
drop policy if exists notes_update_own on public.notes;
drop policy if exists notes_delete_own on public.notes;

create policy notes_select_own on public.notes
  for select to authenticated
  using ((select auth.uid()) = user_id);

create policy notes_insert_own on public.notes
  for insert to authenticated
  with check ((select auth.uid()) = user_id);

create policy notes_update_own on public.notes
  for update to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);

create policy notes_delete_own on public.notes
  for delete to authenticated
  using ((select auth.uid()) = user_id);
