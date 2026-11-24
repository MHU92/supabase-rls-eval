-- Enable Row Level Security on the notes table
alter table public.notes enable row level security;
alter table public.notes force row level security;

-- Signed-out visitors (anon) must not have any access
revoke all on table public.notes from anon;

-- Signed-in users get only the privileges they need; RLS restricts rows
revoke all on table public.notes from authenticated;
grant select, insert, update, delete on table public.notes to authenticated;

-- Read own notes
create policy "notes_select_own"
  on public.notes
  for select
  to authenticated
  using ((select auth.uid()) = user_id);

-- Create own notes
create policy "notes_insert_own"
  on public.notes
  for insert
  to authenticated
  with check ((select auth.uid()) = user_id);

-- Edit own notes (cannot reassign to another user)
create policy "notes_update_own"
  on public.notes
  for update
  to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);

-- Delete own notes
create policy "notes_delete_own"
  on public.notes
  for delete
  to authenticated
  using ((select auth.uid()) = user_id);

-- Index to support the policy filter
create index if not exists notes_user_id_idx on public.notes (user_id);
