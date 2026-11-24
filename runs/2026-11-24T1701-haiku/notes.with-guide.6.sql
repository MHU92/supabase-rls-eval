-- Migration: private notes, owner-only access via RLS
-- Tables already exist; grants are revoked from anon/authenticated and only
-- re-granted to authenticated. Policies are per operation, scoped to the owner.

alter table public.notes enable row level security;

revoke all on table public.notes from anon, authenticated;
grant select, insert, update, delete on table public.notes to authenticated;

create index if not exists notes_user_id_idx
on public.notes using btree (user_id);

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
