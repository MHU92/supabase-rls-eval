-- Access model: owners have full control of their documents and their shares.
-- Shared users can read a document, and can also edit title/content when can_edit is true.
-- Only the owner can delete, change owner_id/id, or change sharing.

-- 1. Remove Supabase's default broad grants and re-grant only what is needed.
revoke all on public.documents from public, anon, authenticated;
revoke all on public.document_shares from public, anon, authenticated;
grant select, insert, update, delete on public.documents to authenticated;
grant select, insert, update, delete on public.document_shares to authenticated;

alter table public.documents enable row level security;
alter table public.document_shares enable row level security;

-- 2. Helper functions. SECURITY DEFINER avoids infinite RLS recursion between the two tables.
create or replace function public.is_document_owner(p_document_id int)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.documents d
    where d.id = p_document_id and d.owner_id = (select auth.uid())
  );
$$;

create or replace function public.can_read_document(p_document_id int)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select public.is_document_owner(p_document_id)
      or exists (
        select 1 from public.document_shares s
        where s.document_id = p_document_id and s.user_id = (select auth.uid())
      );
$$;

create or replace function public.can_edit_document(p_document_id int)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select public.is_document_owner(p_document_id)
      or exists (
        select 1 from public.document_shares s
        where s.document_id = p_document_id
          and s.user_id = (select auth.uid())
          and s.can_edit
      );
$$;

revoke execute on function public.is_document_owner(int) from public, anon;
revoke execute on function public.can_read_document(int) from public, anon;
revoke execute on function public.can_edit_document(int) from public, anon;
grant execute on function public.is_document_owner(int) to authenticated;
grant execute on function public.can_read_document(int) to authenticated;
grant execute on function public.can_edit_document(int) to authenticated;

-- 3. Row policies for public.documents.
create policy documents_select on public.documents
  for select to authenticated
  using (public.can_read_document(id));

create policy documents_insert on public.documents
  for insert to authenticated
  with check (owner_id = (select auth.uid()));

create policy documents_update on public.documents
  for update to authenticated
  using (public.can_edit_document(id))
  with check (public.can_edit_document(id));

create policy documents_delete on public.documents
  for delete to authenticated
  using (public.is_document_owner(id));

-- 4. Column protection: RLS cannot restrict individual columns, so a trigger
--    prevents non-owners (editors) from changing owner_id or id.
create or replace function public.protect_document_owner_columns()
returns trigger
language plpgsql
security invoker
set search_path = ''
as $$
begin
  if (select auth.uid()) is distinct from old.owner_id then
    if new.owner_id is distinct from old.owner_id
       or new.id is distinct from old.id then
      raise exception 'only the document owner can change owner_id or id';
    end if;
  end if;
  return new;
end;
$$;

create trigger documents_protect_owner_columns
  before update on public.documents
  for each row execute function public.protect_document_owner_columns();

-- 5. Row policies for public.document_shares.
-- Owners manage all shares; a shared user can only see their own share row.
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
