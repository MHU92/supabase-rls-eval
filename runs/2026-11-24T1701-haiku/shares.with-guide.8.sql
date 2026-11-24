-- Migration: document sharing with RLS
-- Owners have full control; shared users can read, and edit if can_edit is true.
-- Shared users never delete documents or change sharing.

begin;

-- 1. Enable RLS and set grants (revoke Supabase default grants first)
alter table public.documents enable row level security;
alter table public.document_shares enable row level security;

revoke all on table public.documents from anon, authenticated;
revoke all on table public.document_shares from anon, authenticated;

-- Authenticated users need select/insert/update/delete on documents for owners;
-- shared users rely on policies. Grant the minimum per table.
grant select, insert, update, delete on table public.documents to authenticated;
grant select, insert, update, delete on table public.document_shares to authenticated;

-- 2. Indexes for policy filter columns
create index if not exists document_shares_user_id_idx
  on public.document_shares using btree (user_id);

-- 3. Security definer helpers (break recursion between documents and document_shares)
create schema if not exists private;

-- Documents the current user can edit via a share
create or replace function private.editable_document_ids()
returns setof int
language sql
security definer
set search_path = ''
stable
as $$
  select document_id from public.document_shares
  where user_id = (select auth.uid()) and can_edit
$$;

-- Documents the current user can read via a share
create or replace function private.shared_document_ids()
returns setof int
language sql
security definer
set search_path = ''
stable
as $$
  select document_id from public.document_shares
  where user_id = (select auth.uid())
$$;

-- Documents the current user owns
create or replace function private.owned_document_ids()
returns setof int
language sql
security definer
set search_path = ''
stable
as $$
  select id from public.documents
  where owner_id = (select auth.uid())
$$;

revoke execute on function private.editable_document_ids() from public;
revoke execute on function private.shared_document_ids() from public;
revoke execute on function private.owned_document_ids() from public;
grant usage on schema private to authenticated;
grant execute on function private.editable_document_ids() to authenticated;
grant execute on function private.shared_document_ids() to authenticated;
grant execute on function private.owned_document_ids() to authenticated;

-- 4. documents policies

-- Owners and sharers can read
create policy "documents_select" on public.documents
for select to authenticated
using (
  owner_id = (select auth.uid())
  or id in (select private.shared_document_ids())
);

-- Only owners can insert, and must set themselves as owner
create policy "documents_insert" on public.documents
for insert to authenticated
with check (owner_id = (select auth.uid()));

-- Owners can update everything; editors can update title/content only (owner_id fixed)
create policy "documents_update" on public.documents
for update to authenticated
using (
  owner_id = (select auth.uid())
  or id in (select private.editable_document_ids())
)
with check (
  owner_id = (select auth.uid())
  or (
    id in (select private.editable_document_ids())
    and owner_id = (select d.owner_id from public.documents d where d.id = documents.id)
  )
);

-- Only owners can delete
create policy "documents_delete" on public.documents
for delete to authenticated
using (owner_id = (select auth.uid()));

-- 5. document_shares policies (only owners manage sharing; sharees may read their own rows)

create policy "shares_select" on public.document_shares
for select to authenticated
using (
  user_id = (select auth.uid())
  or document_id in (select private.owned_document_ids())
);

create policy "shares_insert" on public.document_shares
for insert to authenticated
with check (document_id in (select private.owned_document_ids()));

create policy "shares_update" on public.document_shares
for update to authenticated
using (document_id in (select private.owned_document_ids()))
with check (document_id in (select private.owned_document_ids()));

create policy "shares_delete" on public.document_shares
for delete to authenticated
using (document_id in (select private.owned_document_ids()));

commit;
