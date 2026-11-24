-- Enable RLS and restrict default grants so only the policies below apply.
alter table public.documents enable row level security;
alter table public.document_shares enable row level security;

revoke all on public.documents from anon;
revoke all on public.document_shares from anon;
revoke all on public.documents from authenticated;
revoke all on public.document_shares from authenticated;

grant select, insert, update, delete on public.documents to authenticated;
grant select, insert, update, delete on public.document_shares to authenticated;

-- Helper: does the current user have read access to a document (owner or share)?
create or replace function public.can_read_document(doc_id int)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.documents d
    where d.id = doc_id and d.owner_id = (select auth.uid())
  )
  or exists (
    select 1 from public.document_shares s
    where s.document_id = doc_id and s.user_id = (select auth.uid())
  );
$$;

-- Helper: is the current user the owner of a document?
create or replace function public.is_document_owner(doc_id int)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.documents d
    where d.id = doc_id and d.owner_id = (select auth.uid())
  );
$$;

-- Helper: can the current user edit content of a document (owner, or shared with can_edit)?
create or replace function public.can_edit_document(doc_id int)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select public.is_document_owner(doc_id)
  or exists (
    select 1 from public.document_shares s
    where s.document_id = doc_id and s.user_id = (select auth.uid()) and s.can_edit
  );
$$;

revoke execute on function public.can_read_document(int) from public, anon;
revoke execute on function public.is_document_owner(int) from public, anon;
revoke execute on function public.can_edit_document(int) from public, anon;
grant execute on function public.can_read_document(int) to authenticated;
grant execute on function public.is_document_owner(int) to authenticated;
grant execute on function public.can_edit_document(int) to authenticated;

-- documents policies
create policy documents_select on public.documents
  for select to authenticated
  using (public.can_read_document(id));

create policy documents_insert on public.documents
  for insert to authenticated
  with check (owner_id = (select auth.uid()));

-- Owners and users with can_edit may update; the owner column must not change.
create policy documents_update on public.documents
  for update to authenticated
  using (public.can_edit_document(id))
  with check (public.can_edit_document(id) and owner_id = (select owner_id from public.documents where id = documents.id));

-- Only owners may delete.
create policy documents_delete on public.documents
  for delete to authenticated
  using (public.is_document_owner(id));

-- document_shares policies: only the owner manages sharing; shared users may read their own rows.
create policy document_shares_select on public.document_shares
  for select to authenticated
  using (user_id = (select auth.uid()) or public.is_document_owner(document_id));

create policy document_shares_insert on public.document_shares
  for insert to authenticated
  with check (public.is_document_owner(document_id));

create policy document_shares_update on public.document_shares
  for update to authenticated
  using (public.is_document_owner(document_id))
  with check (public.is_document_owner(document_id));

create policy document_shares_delete on public.document_shares
  for delete to authenticated
  using (public.is_document_owner(document_id));
