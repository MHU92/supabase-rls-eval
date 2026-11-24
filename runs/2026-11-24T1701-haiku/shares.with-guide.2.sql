-- Migration: document sharing via RLS
-- Access rule: owners have full control; shared users can read; shared users with can_edit may update title/content only.

begin;

-- 1. Enable RLS and reset grants (existing tables still carry default grants)
alter table public.documents enable row level security;
alter table public.document_shares enable row level security;

revoke all on table public.documents from anon, authenticated;
revoke all on table public.document_shares from anon, authenticated;

grant select, insert, update, delete on table public.documents to authenticated;
grant select, insert, update, delete on table public.document_shares to authenticated;

-- 2. Indexes for policy lookups
-- document_shares PK is (document_id, user_id): covers document_id; user_id needs its own index.
create index if not exists document_shares_user_id_idx
  on public.document_shares using btree (user_id);

-- 3. Helper: documents the current user may read (owned or shared).
-- security definer avoids recursion between the two tables' policies.
create schema if not exists private;

create or replace function private.readable_document_ids()
returns setof int
language sql
security definer
set search_path = ''
stable
as $$
  select d.id from public.documents d where d.owner_id = (select auth.uid())
  union
  select s.document_id from public.document_shares s where s.user_id = (select auth.uid())
$$;

-- Helper: documents the current user may edit (owned, or shared with can_edit).
create or replace function private.editable_document_ids()
returns setof int
language sql
security definer
set search_path = ''
stable
as $$
  select d.id from public.documents d where d.owner_id = (select auth.uid())
  union
  select s.document_id from public.document_shares s
  where s.user_id = (select auth.uid()) and s.can_edit
$$;

revoke execute on function private.readable_document_ids() from public;
revoke execute on function private.editable_document_ids() from public;
grant usage on schema private to authenticated;
grant execute on function private.readable_document_ids() to authenticated;
grant execute on function private.editable_document_ids() to authenticated;

-- 4. documents policies
create policy "owners and sharees can read documents"
on public.documents for select
to authenticated
using ( id in (select private.readable_document_ids()) );

create policy "owners can insert their documents"
on public.documents for insert
to authenticated
with check ( (select auth.uid()) = owner_id );

-- Owners and edit-sharees may update. The owner_id must not change.
create policy "owners and editors can update documents"
on public.documents for update
to authenticated
using ( id in (select private.editable_document_ids()) )
with check (
  id in (select private.editable_document_ids())
  and owner_id = (select owner_id from public.documents where id = documents.id)
);

create policy "owners can delete their documents"
on public.documents for delete
to authenticated
using ( (select auth.uid()) = owner_id );

-- 5. document_shares policies: only the owner manages sharing.
create policy "owners can read shares of their documents"
on public.document_shares for select
to authenticated
using (
  document_id in (select d.id from public.documents d where d.owner_id = (select auth.uid()))
  or user_id = (select auth.uid())
);

create policy "owners can create shares"
on public.document_shares for insert
to authenticated
with check (
  document_id in (select d.id from public.documents d where d.owner_id = (select auth.uid()))
);

create policy "owners can update shares"
on public.document_shares for update
to authenticated
using (
  document_id in (select d.id from public.documents d where d.owner_id = (select auth.uid()))
)
with check (
  document_id in (select d.id from public.documents d where d.owner_id = (select auth.uid()))
);

create policy "owners can delete shares"
on public.document_shares for delete
to authenticated
using (
  document_id in (select d.id from public.documents d where d.owner_id = (select auth.uid()))
);

commit;
