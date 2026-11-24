-- Migration: RLS for public.notes (owner-only access, signed-in users only)

alter table public.notes enable row level security;

-- Revoke the default grants from client roles, then grant back only what signed-in users need.
revoke all on table public.notes from anon, authenticated;
grant select, insert, update, delete on table public.notes to authenticated;

-- Index the filter column used by every policy.
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
