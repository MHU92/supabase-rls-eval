-- Row Level Security for documents and document_shares.
-- Owners have full control of their documents and decide who they are shared with.
-- Shared users can read; users with can_edit = true can also change title and content.

-- 1. Remove Supabase's default broad grants and enable RLS.
revoke all on public.documents from anon, authenticated;
revoke all on public.document_shares from anon, authenticated;

grant select, insert, update, delete on public.documents to authenticated;
grant select, insert, update, delete on public.document_shares to authenticated;

alter table public.documents enable row level security;
alter table public.document_shares enable row level security;

-- 2. Helper functions. SECURITY DEFINER with an empty search_path avoids
--    infinite recursion between the policies of the two tables.
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
      and d.owner_id = (select auth.uid())
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
        select 1
        from public.document_shares s
        where s.document_id = p_document_id
          and s.user_id = (select auth.uid())
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
        select 1
        from public.document_shares s
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

-- 3. Trigger: only the owner may change id or owner_id.
--    Editors may change title and content through the UPDATE policy.
create or replace function public.guard_document_update()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if (new.id is distinct from old.id or new.owner_id is distinct from old.owner_id)
     and auth.uid() is not null
     and auth.uid() is distinct from old.owner_id then
    raise exception 'only the owner can change id or owner_id of a document';
  end if;
  return new;
end;
$$;

create trigger documents_guard_update
  before update on public.documents
  for each row execute function public.guard_document_update();

-- 4. Policies for public.documents
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

-- 5. Policies for public.document_shares
-- Recipients can see the grants that apply to them. Only the owner manages sharing.
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
