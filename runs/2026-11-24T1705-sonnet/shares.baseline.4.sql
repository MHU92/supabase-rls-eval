-- Helper schema (not exposed through the API)
create schema if not exists private;
revoke all on schema private from public, anon;
grant usage on schema private to authenticated;

-- Helper functions run as definer to avoid RLS recursion between the two tables
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

create or replace function private.has_document_share(_document_id int, _need_edit boolean)
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

revoke all on function private.is_document_owner(int) from public, anon;
revoke all on function private.has_document_share(int, boolean) from public, anon;
grant execute on function private.is_document_owner(int) to authenticated;
grant execute on function private.has_document_share(int, boolean) to authenticated;

-- Lock down default grants: no anonymous access
revoke all on public.documents from anon;
revoke all on public.document_shares from anon;

alter table public.documents enable row level security;
alter table public.document_shares enable row level security;

-- documents
create policy documents_select on public.documents
  for select to authenticated
  using (
    owner_id = (select auth.uid())
    or private.has_document_share(id, false)
  );

create policy documents_insert on public.documents
  for insert to authenticated
  with check (owner_id = (select auth.uid()));

create policy documents_update on public.documents
  for update to authenticated
  using (
    owner_id = (select auth.uid())
    or private.has_document_share(id, true)
  )
  with check (
    owner_id = (select auth.uid())
    or private.has_document_share(id, true)
  );

create policy documents_delete on public.documents
  for delete to authenticated
  using (owner_id = (select auth.uid()));

-- Only the current owner may change owner_id (editors may only change title/content)
create or replace function private.documents_protect_owner()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if new.owner_id is distinct from old.owner_id
     and (select auth.uid()) is not null
     and (select auth.uid()) is distinct from old.owner_id then
    raise exception 'only the owner can change owner_id';
  end if;
  return new;
end;
$$;

create trigger documents_protect_owner
  before update on public.documents
  for each row execute function private.documents_protect_owner();

-- document_shares
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
