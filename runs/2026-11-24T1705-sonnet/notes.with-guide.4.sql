-- Enable RLS on the notes table
alter table public.notes enable row level security;

-- Remove the default grants from both client roles (policies alone don't revoke them)
revoke all on table public.notes from anon, authenticated;

-- Signed-in users manage their own notes; signed-out visitors get nothing
grant select, insert, update, delete on table public.notes to authenticated;

-- SELECT: users can read only their own notes
create policy "Users can view their own notes."
on public.notes for select
to authenticated
using ( (select auth.uid()) is not null and (select auth.uid()) = user_id );

-- INSERT: users can create notes only for themselves
create policy "Users can create their own notes."
on public.notes for insert
to authenticated
with check ( (select auth.uid()) is not null and (select auth.uid()) = user_id );

-- UPDATE: users can edit only their own notes and cannot reassign them to someone else
create policy "Users can update their own notes."
on public.notes for update
to authenticated
using ( (select auth.uid()) is not null and (select auth.uid()) = user_id )
with check ( (select auth.uid()) is not null and (select auth.uid()) = user_id );

-- DELETE: users can delete only their own notes
create policy "Users can delete their own notes."
on public.notes for delete
to authenticated
using ( (select auth.uid()) is not null and (select auth.uid()) = user_id );

-- Index the column the policies filter on
create index notes_user_id_idx on public.notes using btree (user_id);
