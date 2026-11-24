-- Migration: private notes with RLS (owner-only access for signed-in users)
-- Signed-out visitors (anon) get no grants and no policies, so they can neither read nor change anything.

alter table public.notes enable row level security;

-- Remove default grants from client roles; re-grant only what signed-in users need.
revoke all on table public.notes from anon, authenticated;
grant select, insert, update, delete on table public.notes to authenticated;

-- Index for policy filtering on user_id.
create index if not exists notes_user_id_idx on public.notes using btree (user_id);

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
