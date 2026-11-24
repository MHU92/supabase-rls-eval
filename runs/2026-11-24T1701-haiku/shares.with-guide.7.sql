-- Migration: document access via ownership and sharing
-- Owners: full control over their documents and the sharing list.
-- Shared users: SELECT always; UPDATE of title/content only when can_edit.
-- Owner cannot be changed; shared users cannot delete or touch sharing.

-- 1. Enable RLS and reset grants (table currently has default grants).
alter table public.documents enable row level security;
alter table public.document_shares enable row level security;

revoke all on table public.documents from anon, authenticated;
revoke all on table public.document_shares from anon, authenticated;

grant select, insert, update, delete on table public.documents to authenticated;
grant select, insert, update, delete on table public.document_shares to authenticated;

-- 2. Indexes for policy filter columns.
create index if not exists document_shares_user_id_idx
  on public.document_shares using btree (user_id);

-- 3. Helper: ids of documents shared with the caller with edit rights.
--    Security definer avoids recursion between the two tables' policies.
create schema if not exists private;

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

create or replace function private.readable_document_ids()
returns setof int
language sql
security definer
set search_path = ''
stable
as $$
  select document_id from public.document_shares
  where user_id = (select auth.uid())
$$;

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
revoke execute on function private.readable_document_ids() from public;
revoke execute on function private.owned_document_ids() from public;
grant usage on schema private to authenticated;
grant execute on function private.editable_document_ids() to authenticated;
grant execute on function private.readable_document_ids() to authenticated;
grant execute on function private.owned_document_ids() to authenticated;

-- 4. documents policies
create policy "documents_select_owner_or_shared"
on public.documents for select
to authenticated
using (
  owner_id = (select auth.uid())
  or id in (select private.readable_document_ids())
);

create policy "documents_insert_owner"
on public.documents for insert
to authenticated
with check ( owner_id = (select auth.uid()) );

-- Owner may update anything; editors may update title/content only
-- (owner_id and id are pinned via the with check comparison to the existing row).
create policy "documents_update_owner_or_editor"
on public.documents for update
to authenticated
using (
  owner_id = (select auth.uid())
  or id in (select private.editable_document_ids())
)
with check (
  owner_id = (select auth.uid())
  or (
    id in (select private.editable_document_ids())
    and owner_id = (select owner_id from public.documents d where d.id = documents.id)
  )
);

create policy "documents_delete_owner"
on public.documents for delete
to authenticated
using ( owner_id = (select auth.uid()) );

-- 5. document_shares policies (only the document owner manages sharing)
create policy "shares_select_owner_or_recipient"
on public.document_shares for select
to authenticated
using (
  user_id = (select auth.uid())
  or document_id in (select private.owned_document_ids())
);

create policy "shares_insert_owner"
on public.document_shares for insert
to authenticated
with check ( document_id in (select private.owned_document_ids()) );

create policy "shares_update_owner"
on public.document_shares for update
to authenticated
using ( document_id in (select private.owned_document_ids()) )
with check ( document_id in (select private.owned_document_ids()) );

create policy "shares_delete_owner"
on public.document_shares for delete
to authenticated
using ( document_id in (select private.owned_document_ids()) );
