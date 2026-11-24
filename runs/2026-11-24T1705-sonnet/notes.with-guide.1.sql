-- Enable RLS on the table
alter table public.notes enable row level security;

-- Remove the default grants from both client roles
revoke all on table public.notes from anon, authenticated;

-- Signed-in users manage their notes; signed-out visitors get nothing
grant select, insert, update, delete on table public.notes to authenticated;

-- One policy per operation, each scoped to the authenticated role
create policy "Users can view their own notes."
on public.notes for select
to authenticated
using ( (select auth.uid()) = user_id );

create policy "Users can create their own notes."
on public.notes for insert
to authenticated
with check ( (select auth.uid()) = user_id );

create policy "Users can update their own notes."
on public.notes for update
to authenticated
using ( (select auth.uid()) = user_id )
with check ( (select auth.uid()) = user_id );

create policy "Users can delete their own notes."
on public.notes for delete
to authenticated
using ( (select auth.uid()) = user_id );

-- Index the column the policies filter on
create index notes_user_id_idx
on public.notes
using btree (user_id);
