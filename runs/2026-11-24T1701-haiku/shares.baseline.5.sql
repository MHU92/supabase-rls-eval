begin;

-- Enforce RLS and remove Supabase's default table grants
alter table public.documents enable row level security;
alter table public.document_shares enable row level security;

revoke all on public.documents from anon, authenticated;
revoke all on public.document_shares from anon, authenticated;
grant select, insert, update, delete on public.documents to authenticated;
grant select, insert, update, delete on public.document_shares to authenticated;

-- Helper functions run as definer so policies on one table do not recurse into the other table's policies
create or replace function public.is_document_owner(doc_id int)
returns boolean
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select exists (
    select 1 from public.documents d
    where d.id = doc_id and d.owner_id = auth.uid()
  );
$$;

create or replace function public.can_read_document(doc_id int)
returns boolean
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select exists (
    select 1 from public.documents d
    where d.id = doc_id and d.owner_id = auth.uid()
  )
  or exists (
    select 1 from public.document_shares s
    where s.document_id = doc_id and s.user_id = auth.uid()
  );
$$;

create or replace function public.can_edit_document(doc_id int)
returns boolean
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select exists (
    select 1 from public.documents d
    where d.id = doc_id and d.owner_id = auth.uid()
  )
  or exists (
    select 1 from public.document_shares s
    where s.document_id = doc_id and s.user_id = auth.uid() and s.can_edit
  );
$$;

revoke execute on function public.is_document_owner(int) from public, anon;
revoke execute on function public.can_read_document(int) from public, anon;
revoke execute on function public.can_edit_document(int) from public, anon;
grant execute on function public.is_document_owner(int) to authenticated;
grant execute on function public.can_read_document(int) to authenticated;
grant execute on function public.can_edit_document(int) to authenticated;

-- Editors may change title and content only; owner_id and id are protected here
-- because RLS cannot restrict individual columns
create or replace function public.protect_document_identity()
returns trigger
language plpgsql
set search_path = public, pg_temp
as $$
begin
  if auth.uid() is not null
     and auth.uid() is distinct from old.owner_id
     and (new.id is distinct from old.id or new.owner_id is distinct from old.owner_id) then
    raise exception 'only the owner may change id or owner_id of a document';
  end if;
  return new;
end;
$$;

drop trigger if exists protect_document_identity on public.documents;
create trigger protect_document_identity
  before update on public.documents
  for each row execute function public.protect_document_identity();

-- Documents policies
drop policy if exists documents_select on public.documents;
drop policy if exists documents_insert on public.documents;
drop policy if exists documents_update on public.documents;
drop policy if exists documents_delete on public.documents;

create policy documents_select on public.documents
  for select to authenticated
  using (public.can_read_document(id));

create policy documents_insert on public.documents
  for insert to authenticated
  with check (owner_id = auth.uid());

create policy documents_update on public.documents
  for update to authenticated
  using (public.can_edit_document(id))
  with check (public.can_edit_document(id));

create policy documents_delete on public.documents
  for delete to authenticated
  using (public.is_document_owner(id));

-- Only owners manage sharing
drop policy if exists document_shares_owner_all on public.document_shares;

create policy document_shares_owner_all on public.document_shares
  for all to authenticated
  using (public.is_document_owner(document_id))
  with check (public.is_document_owner(document_id));

commit;
