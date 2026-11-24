-- Row Level Security for documents and document_shares.
-- Owners have full control. Users with a share can read the document,
-- and can edit title/content when can_edit is true. Only the owner can
-- change ownership, delete the document, or change sharing.

-- 1. Remove Supabase's default broad grants; RLS policies below grant access.
revoke all on public.documents from anon, authenticated;
revoke all on public.document_shares from anon, authenticated;
grant select, insert, update, delete on public.documents to authenticated;
grant select, insert, update, delete on public.document_shares to authenticated;

-- 2. Enable RLS.
alter table public.documents enable row level security;
alter table public.document_shares enable row level security;

-- 3. Helper functions (SECURITY DEFINER) so policies on one table do not
--    recurse into policies on the other table.
create or replace function public.is_document_owner(doc_id int)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.documents d
    where d.id = doc_id and d.owner_id = auth.uid()
  );
$$;

create or replace function public.has_document_share(doc_id int)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.document_shares s
    where s.document_id = doc_id and s.user_id = auth.uid()
  );
$$;

create or replace function public.can_edit_document(doc_id int)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.document_shares s
    where s.document_id = doc_id and s.user_id = auth.uid() and s.can_edit
  );
$$;

revoke execute on function public.is_document_owner(int) from public, anon;
revoke execute on function public.has_document_share(int) from public, anon;
revoke execute on function public.can_edit_document(int) from public, anon;
grant execute on function public.is_document_owner(int) to authenticated;
grant execute on function public.has_document_share(int) to authenticated;
grant execute on function public.can_edit_document(int) to authenticated;

-- 4. Policies for public.documents.
create policy documents_select on public.documents
  for select to authenticated
  using (owner_id = auth.uid() or public.has_document_share(id));

create policy documents_insert on public.documents
  for insert to authenticated
  with check (owner_id = auth.uid());

-- Owners may update everything, including ownership.
create policy documents_owner_update on public.documents
  for update to authenticated
  using (owner_id = auth.uid())
  with check (true);

-- Editors may update the row; a trigger restricts which columns they may change.
create policy documents_editor_update on public.documents
  for update to authenticated
  using (public.can_edit_document(id))
  with check (public.can_edit_document(id));

-- Only owners may delete.
create policy documents_owner_delete on public.documents
  for delete to authenticated
  using (owner_id = auth.uid());

-- 5. Trigger: non-owners (editors) may not change id or owner_id.
create or replace function public.documents_guard_non_owner_update()
returns trigger
language plpgsql
security invoker
set search_path = public
as $$
begin
  if auth.uid() is not null and auth.uid() is distinct from old.owner_id then
    if new.id is distinct from old.id
       or new.owner_id is distinct from old.owner_id then
      raise exception 'Only the document owner can change the id or owner of a document';
    end if;
  end if;
  return new;
end;
$$;

create trigger documents_guard_non_owner_update
  before update on public.documents
  for each row execute function public.documents_guard_non_owner_update();

-- 6. Policies for public.document_shares. Only the owner manages shares.
--    A shared user may read their own share row.
create policy shares_select on public.document_shares
  for select to authenticated
  using (user_id = auth.uid() or public.is_document_owner(document_id));

create policy shares_owner_insert on public.document_shares
  for insert to authenticated
  with check (public.is_document_owner(document_id));

create policy shares_owner_update on public.document_shares
  for update to authenticated
  using (public.is_document_owner(document_id))
  with check (public.is_document_owner(document_id));

create policy shares_owner_delete on public.document_shares
  for delete to authenticated
  using (public.is_document_owner(document_id));
