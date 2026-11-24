-- Migration: enforce owner-only access to public.notes via RLS
-- Signed-in users: select/insert/update/delete own rows only.
-- Signed-out (anon): no access at all.

alter table public.notes enable row level security;

-- Remove default grants for client roles; re-grant only what authenticated needs.
revoke all on table public.notes from anon, authenticated;
grant select, insert, update, delete on table public.notes to authenticated;

-- Index the policy filter column (needed for performance on existing data).
create index if not exists notes_user_id_idx on public.notes using btree (user_id);

create policy "Users can read their own notes"
on public.notes for select
to authenticated
using ( (select auth.uid()) = user_id );

create policy "Users can create their own notes"
on public.notes for insert
to authenticated
with check ( (select auth.uid()) = user_id );

create policy "Users can update their own notes"
on public.notes for update
to authenticated
using ( (select auth.uid()) = user_id )
with check ( (select auth.uid()) = user_id );

create policy "Users can delete their own notes"
on public.notes for delete
to authenticated
using ( (select auth.uid()) = user_id );
