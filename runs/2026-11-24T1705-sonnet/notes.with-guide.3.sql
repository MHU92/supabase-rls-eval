-- Enable RLS on the private notes table
alter table public.notes enable row level security;

-- Remove Supabase's default grants from both client roles
revoke all on table public.notes from anon, authenticated;

-- Signed-in users manage notes; signed-out visitors (anon) get nothing
grant select, insert, update, delete on table public.notes to authenticated;

-- Index the column the policies filter on
create index notes_user_id_idx on public.notes using btree (user_id);

-- SELECT: users read only their own notes
create policy "Users can view their own notes."
on public.notes for select
to authenticated
using ( (select auth.uid()) is not null and (select auth.uid()) = user_id );

-- INSERT: users create notes only for themselves
create policy "Users can create their own notes."
on public.notes for insert
to authenticated
with check ( (select auth.uid()) is not null and (select auth.uid()) = user_id );

-- UPDATE: users edit only their own notes and cannot reassign ownership
create policy "Users can update their own notes."
on public.notes for update
to authenticated
using ( (select auth.uid()) is not null and (select auth.uid()) = user_id )
with check ( (select auth.uid()) is not null and (select auth.uid()) = user_id );

-- DELETE: users delete only their own notes
create policy "Users can delete their own notes."
on public.notes for delete
to authenticated
using ( (select auth.uid()) is not null and (select auth.uid()) = user_id );
