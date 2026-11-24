-- Enable RLS on the table
alter table public.notes enable row level security;

-- Remove default grants from both client roles, then grant back only what is needed
revoke all on table public.notes from anon, authenticated;
grant select, insert, update, delete on table public.notes to authenticated;

-- Signed-in users can read only their own notes
create policy "Users can view their own notes."
on public.notes for select
to authenticated
using ( (select auth.uid()) = user_id );

-- Signed-in users can create notes only for themselves
create policy "Users can create their own notes."
on public.notes for insert
to authenticated
with check ( (select auth.uid()) = user_id );

-- Signed-in users can edit only their own notes and cannot reassign them
create policy "Users can update their own notes."
on public.notes for update
to authenticated
using ( (select auth.uid()) = user_id )
with check ( (select auth.uid()) = user_id );

-- Signed-in users can delete only their own notes
create policy "Users can delete their own notes."
on public.notes for delete
to authenticated
using ( (select auth.uid()) = user_id );

-- Index the column the policies filter on
create index notes_user_id_idx on public.notes using btree (user_id);
