begin;

alter table public.notes enable row level security;
alter table public.notes force row level security;

revoke all on table public.notes from anon;
revoke all on table public.notes from public;
grant select, insert, update, delete on table public.notes to authenticated;

drop policy if exists notes_select_own on public.notes;
drop policy if exists notes_insert_own on public.notes;
drop policy if exists notes_update_own on public.notes;
drop policy if exists notes_delete_own on public.notes;

create policy notes_select_own on public.notes
  for select to authenticated
  using (user_id = (select auth.uid()));

create policy notes_insert_own on public.notes
  for insert to authenticated
  with check (user_id = (select auth.uid()));

create policy notes_update_own on public.notes
  for update to authenticated
  using (user_id = (select auth.uid()))
  with check (user_id = (select auth.uid()));

create policy notes_delete_own on public.notes
  for delete to authenticated
  using (user_id = (select auth.uid()));

commit;
