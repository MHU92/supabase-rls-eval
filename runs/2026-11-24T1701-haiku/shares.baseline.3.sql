-- Row Level Security for documents and document_shares.
-- Owners have full control over their documents and their shares.
-- Shared users can read; users with can_edit may also change title and content.
-- Only the owner may change owner_id (and id, which is the primary key).

-- 1. Remove Supabase's default broad grants and re-grant only what is needed.
revoke all on public.documents from anon, authenticated;
revoke all on public.document_shares from anon, authenticated;

grant select, insert, update, delete on public.documents to authenticated;
grant select, insert, update, delete on public.document_shares to authenticated;

-- 2. Enable RLS.
alter table public.documents enable row level security;
alter table public.document_shares enable row level security;

-- 3. Helper functions. SECURITY DEFINER avoids infinite recursion between the
--    two tables' policies (each policy references the other table).
create or replace function public.is_document_owner(p_document_id int)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.documents d
    where d.id = p_document_id
      and d.owner_id = auth.uid()
  );
$$;

create or replace function public.can_read_document(p_document_id int)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.document_shares s
    where s.document_id = p_document_id
      and s.user_id = auth.uid()
  );
$$;

create or replace function public.can_edit_document(p_document_id int)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.document_shares s
    where s.document_id = p_document_id
      and s.user_id = auth.uid()
      and s.can_edit
  );
$$;

revoke execute on function public.is_document_owner(int) from public, anon;
revoke execute on function public.can_read_document(int) from public, anon;
revoke execute on function public.can_edit_document(int) from public, anon;
grant execute on function public.is_document_owner(int) to authenticated;
grant execute on function public.can_read_document(int) to authenticated;
grant execute on function public.can_edit_document(int) to authenticated;

-- 4. Trigger: RLS works per row, not per column, so protect id and owner_id here.
--    Only the owner of the existing row may change id or owner_id.
create or replace function public.documents_protect_identity()
returns trigger
language plpgsql
security invoker
set search_path = ''
as $$
begin
  if (new.id is distinct from old.id or new.owner_id is distinct from old.owner_id)
     and old.owner_id is distinct from auth.uid() then
    raise exception 'only the owner may change id or owner_id of a document'
      using errcode = '42501';
  end if;
  return new;
end;
$$;

drop trigger if exists documents_protect_identity on public.documents;
create trigger documents_protect_identity
  before update on public.documents
  for each row
  execute function public.documents_protect_identity();

-- 5. Policies for public.documents.
drop policy if exists documents_select on public.documents;
drop policy if exists documents_insert on public.documents;
drop policy if exists documents_update on public.documents;
drop policy if exists documents_delete on public.documents;

create policy documents_select on public.documents
  for select to authenticated
  using (
    owner_id = auth.uid()
    or public.can_read_document(id)
  );

create policy documents_insert on public.documents
  for insert to authenticated
  with check (
    owner_id = auth.uid()
  );

create policy documents_update on public.documents
  for update to authenticated
  using (
    owner_id = auth.uid()
    or public.can_edit_document(id)
  )
  with check (
    owner_id = auth.uid()
    or public.can_edit_document(id)
  );

create policy documents_delete on public.documents
  for delete to authenticated
  using (
    owner_id = auth.uid()
  );

-- 6. Policies for public.document_shares. Only the document owner manages shares.
--    A shared user can see their own share row.
drop policy if exists document_shares_select on public.document_shares;
drop policy if exists document_shares_insert on public.document_shares;
drop policy if exists document_shares_update on public.document_shares;
drop policy if exists document_shares_delete on public.document_shares;

create policy document_shares_select on public.document_shares
  for select to authenticated
  using (
    user_id = auth.uid()
    or public.is_document_owner(document_id)
  );

create policy document_shares_insert on public.document_shares
  for insert to authenticated
  with check (
    public.is_document_owner(document_id)
  );

create policy document_shares_update on public.document_shares
  for update to authenticated
  using (
    public.is_document_owner(document_id)
  )
  with check (
    public.is_document_owner(document_id)
  );

create policy document_shares_delete on public.document_shares
  for delete to authenticated
  using (
    public.is_document_owner(document_id)
  );
