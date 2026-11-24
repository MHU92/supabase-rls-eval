-- Helper functions (SECURITY DEFINER to avoid RLS recursion between the two tables)
create schema if not exists private;
revoke all on schema private from public;
grant usage on schema private to authenticated;

create or replace function private.is_document_owner(_document_id int)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.documents d
    where d.id = _document_id
      and d.owner_id = (select auth.uid())
  );
$$;

create or replace function private.has_document_share(_document_id int, _need_edit boolean default false)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.document_shares s
    where s.document_id = _document_id
      and s.user_id = (select auth.uid())
      and (not _need_edit or s.can_edit)
  );
$$;

revoke all on function private.is_document_owner(int) from public;
revoke all on function private.has_document_share(int, boolean) from public;
grant execute on function private.is_document_owner(int) to authenticated;
grant execute on function private.has_document_share(int, boolean) to authenticated;

-- Enable RLS
alter table public.documents enable row level security;
alter table public.document_shares enable row level security;

-- Grants: no anonymous access; authenticated only gets what is needed
revoke all on public.documents from anon;
revoke all on public.document_shares from anon;

-- Updates to documents are limited to title/content (owner_id and id can never change)
revoke update on public.documents from authenticated;
grant update (title, content) on public.documents to authenticated;

-- documents policies
create policy documents_select on public.documents
  for select to authenticated
  using (
    owner_id = (select auth.uid())
    or private.has_document_share(id)
  );

create policy documents_insert on public.documents
  for insert to authenticated
  with check (owner_id = (select auth.uid()));

create policy documents_update_owner on public.documents
  for update to authenticated
  using (owner_id = (select auth.uid()))
  with check (owner_id = (select auth.uid()));

create policy documents_update_shared_editor on public.documents
  for update to authenticated
  using (private.has_document_share(id, true))
  with check (private.has_document_share(id, true));

create policy documents_delete on public.documents
  for delete to authenticated
  using (owner_id = (select auth.uid()));

-- document_shares policies
create policy shares_select on public.document_shares
  for select to authenticated
  using (
    user_id = (select auth.uid())
    or private.is_document_owner(document_id)
  );

create policy shares_insert on public.document_shares
  for insert to authenticated
  with check (private.is_document_owner(document_id));

create policy shares_update on public.document_shares
  for update to authenticated
  using (private.is_document_owner(document_id))
  with check (private.is_document_owner(document_id));

create policy shares_delete on public.document_shares
  for delete to authenticated
  using (private.is_document_owner(document_id));

-- Supporting index for share lookups by user
create index if not exists document_shares_user_id_idx on public.document_shares (user_id);
