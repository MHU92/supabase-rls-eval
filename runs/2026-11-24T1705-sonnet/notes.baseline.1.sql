-- Enable Row Level Security on the notes table
alter table public.notes enable row level security;
alter table public.notes force row level security;

-- Signed-out visitors (anon) must not have any access
revoke all on table public.notes from anon;

-- Signed-in users get only the privileges they need; RLS restricts them to their own rows
revoke all on table public.notes from authenticated;
grant select, insert, update, delete on table public.notes to authenticated;

-- Read own notes
create policy "Users can read their own notes"
  on public.notes
  for select
  to authenticated
  using ((select auth.uid()) = user_id);

-- Create notes only for themselves
create policy "Users can insert their own notes"
  on public.notes
  for insert
  to authenticated
  with check ((select auth.uid()) = user_id);

-- Edit own notes, and prevent reassigning them to someone else
create policy "Users can update their own notes"
  on public.notes
  for update
  to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);

-- Delete own notes
create policy "Users can delete their own notes"
  on public.notes
  for delete
  to authenticated
  using ((select auth.uid()) = user_id);
