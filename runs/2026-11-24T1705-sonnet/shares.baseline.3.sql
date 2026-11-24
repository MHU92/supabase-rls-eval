-- Helper in a non-exposed schema. SECURITY DEFINER bypasses RLS on documents,
-- which avoids infinite policy recursion between documents and document_shares.
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
    where d.id = doc_id and d.owner_id = (select auth.uid())
  );
$$;

revoke all on function private.is_document_owner(int) from public;
grant execute on function private.is_document_owner(int) to authenticated;

-- Enable RLS
alter table public.documents enable row level security;
alter table public.document_shares enable row level security;

-- Tighten default grants: no anonymous access, authenticated only what is needed
revoke all on public.documents from anon, authenticated;
revoke all on public.document_shares from anon, authenticated;
grant select, insert, update, delete on public.documents to authenticated;
grant select, insert, update, delete on public.document_shares to authenticated;

-- documents policies
create policy documents_select on public.documents
  for select to authenticated
  using (
    owner_id = (select auth.uid())
    or exists (
      select 1 from public.document_shares s
      where s.document_id = documents.id
        and s.user_id = (select auth.uid())
    )
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
  using (
    exists (
      select 1 from public.document_shares s
      where s.document_id = documents.id
        and s.user_id = (select auth.uid())
        and s.can_edit
    )
  )
  with check (
    exists (
      select 1 from public.document_shares s
      where s.document_id = documents.id
        and s.user_id = (select auth.uid())
        and s.can_edit
    )
  );

create policy documents_delete on public.documents
  for delete to authenticated
  using (owner_id = (select auth.uid()));

-- Non-owners (shared editors) may not change owner_id or id.
create or replace function private.documents_protect_columns()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if (select auth.uid()) is not null
     and (select auth.uid()) is distinct from old.owner_id
     and (new.owner_id is distinct from old.owner_id or new.id is distinct from old.id)
  then
    raise exception 'only the owner may change owner_id or id'
      using errcode = '42501';
  end if;
  return new;
end;
$$;

create trigger documents_protect_columns
  before update on public.documents
  for each row execute function private.documents_protect_columns();

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
