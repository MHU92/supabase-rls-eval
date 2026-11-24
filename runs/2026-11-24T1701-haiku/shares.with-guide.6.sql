-- Access model:
--   owner:   full control over their documents, including sharing
--   shared:  read; with can_edit, update title and content only
--   nobody but the owner may delete, change owner_id, or change sharing

alter table public.documents enable row level security;
alter table public.document_shares enable row level security;

create schema if not exists private;

-- Security definer helpers break the policy cycle between documents and
-- document_shares: each policy reads the other table as the function owner,
-- so the other table's policies are not evaluated.
create or replace function private.is_doc_owner(p_doc_id int)
returns boolean
language sql
security definer
stable
set search_path = ''
as $$
  select exists (
    select 1 from public.documents d
    where d.id = p_doc_id and d.owner_id = (select auth.uid())
  );
$$;

create or replace function private.has_doc_share(p_doc_id int, p_need_edit boolean)
returns boolean
language sql
security definer
stable
set search_path = ''
as $$
  select exists (
    select 1 from public.document_shares s
    where s.document_id = p_doc_id
      and s.user_id = (select auth.uid())
      and (not p_need_edit or s.can_edit)
  );
$$;

revoke execute on function private.is_doc_owner(int) from public;
revoke execute on function private.has_doc_share(int, boolean) from public;
grant usage on schema private to authenticated;
grant execute on function private.is_doc_owner(int) to authenticated;
grant execute on function private.has_doc_share(int, boolean) to authenticated;

-- Grants: strip the default privileges, then grant back only what is needed.
revoke all on table public.documents from anon, authenticated;
revoke all on table public.document_shares from anon, authenticated;

grant select, insert, delete on table public.documents to authenticated;
-- Column-level grant: id and owner_id cannot be changed through the API by anyone.
grant update (title, content) on table public.documents to authenticated;
grant select, insert, update, delete on table public.document_shares to authenticated;

-- documents policies
create policy "documents_select"
on public.documents for select
to authenticated
using (
  owner_id = (select auth.uid())
  or private.has_doc_share(id, false)
);

create policy "documents_insert"
on public.documents for insert
to authenticated
with check ( owner_id = (select auth.uid()) );

create policy "documents_update_owner"
on public.documents for update
to authenticated
using ( owner_id = (select auth.uid()) )
with check ( owner_id = (select auth.uid()) );

create policy "documents_update_editor"
on public.documents for update
to authenticated
using ( private.has_doc_share(id, true) )
with check ( private.has_doc_share(id, true) );

create policy "documents_delete_owner"
on public.documents for delete
to authenticated
using ( owner_id = (select auth.uid()) );

-- document_shares policies
create policy "document_shares_select"
on public.document_shares for select
to authenticated
using (
  user_id = (select auth.uid())
  or private.is_doc_owner(document_id)
);

create policy "document_shares_insert_owner"
on public.document_shares for insert
to authenticated
with check ( private.is_doc_owner(document_id) );

create policy "document_shares_update_owner"
on public.document_shares for update
to authenticated
using ( private.is_doc_owner(document_id) )
with check ( private.is_doc_owner(document_id) );

create policy "document_shares_delete_owner"
on public.document_shares for delete
to authenticated
using ( private.is_doc_owner(document_id) );

-- Indexes for policy filter columns.
-- (document_id, user_id) is already covered by the primary key.
create index if not exists document_shares_user_id_idx
  on public.document_shares (user_id);
create index if not exists documents_owner_id_idx
  on public.documents (owner_id);
