-- Helper in a private schema: bypasses RLS to avoid policy recursion
-- between documents and document_shares.
create schema if not exists private;
revoke all on schema private from public;
grant usage on schema private to authenticated;

create or replace function private.is_document_owner(doc_id int)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.documents d
    where d.id = doc_id and d.owner_id = auth.uid()
  );
$$;

revoke all on function private.is_document_owner(int) from public;
grant execute on function private.is_document_owner(int) to authenticated;

-- Grants: no anonymous access, signed-in users governed by RLS
revoke all on public.documents from anon;
revoke all on public.document_shares from anon;
revoke all on public.documents from authenticated;
revoke all on public.document_shares from authenticated;
grant select, insert, update, delete on public.documents to authenticated;
grant select, insert, update, delete on public.document_shares to authenticated;

alter table public.documents enable row level security;
alter table public.document_shares enable row level security;

-- documents: owner
create policy documents_owner_select on public.documents
  for select to authenticated
  using (owner_id = (select auth.uid()));

create policy documents_owner_insert on public.documents
  for insert to authenticated
  with check (owner_id = (select auth.uid()));

create policy documents_owner_update on public.documents
  for update to authenticated
  using (owner_id = (select auth.uid()))
  with check (true);  -- owner may transfer ownership; guarded by trigger below

create policy documents_owner_delete on public.documents
  for delete to authenticated
  using (owner_id = (select auth.uid()));

-- documents: shared users
create policy documents_shared_select on public.documents
  for select to authenticated
  using (exists (
    select 1 from public.document_shares s
    where s.document_id = documents.id
      and s.user_id = (select auth.uid())
  ));

create policy documents_shared_update on public.documents
  for update to authenticated
  using (exists (
    select 1 from public.document_shares s
    where s.document_id = documents.id
      and s.user_id = (select auth.uid())
      and s.can_edit
  ))
  with check (exists (
    select 1 from public.document_shares s
    where s.document_id = documents.id
      and s.user_id = (select auth.uid())
      and s.can_edit
  ));

-- Only the current owner may change owner_id
create or replace function private.documents_protect_owner()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if new.owner_id is distinct from old.owner_id
     and auth.uid() is not null
     and auth.uid() is distinct from old.owner_id then
    raise exception 'only the owner can change owner_id'
      using errcode = '42501';
  end if;
  return new;
end;
$$;

create trigger documents_protect_owner
  before update on public.documents
  for each row execute function private.documents_protect_owner();

-- document_shares: owners manage, recipients can see their own share rows
create policy shares_select on public.document_shares
  for select to authenticated
  using (
    user_id = (select auth.uid())
    or private.is_document_owner(document_id)
  );

create policy shares_owner_insert on public.document_shares
  for insert to authenticated
  with check (private.is_document_owner(document_id));

create policy shares_owner_update on public.document_shares
  for update to authenticated
  using (private.is_document_owner(document_id))
  with check (private.is_document_owner(document_id));

create policy shares_owner_delete on public.document_shares
  for delete to authenticated
  using (private.is_document_owner(document_id));

create index if not exists document_shares_user_id_idx
  on public.document_shares (user_id);
create index if not exists documents_owner_id_idx
  on public.documents (owner_id);
