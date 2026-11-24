-- Access model: owners have full control; shared users can read, and can also
-- update title/content when can_edit is true. Only owners may delete, change
-- ownership, or manage sharing.

-- 1. Remove Supabase's default broad grants; RLS policies below grant the actual access.
revoke all on public.documents from anon, authenticated;
revoke all on public.document_shares from anon, authenticated;

grant select, insert, update, delete on public.documents to authenticated;
grant select, insert, update, delete on public.document_shares to authenticated;

-- 2. Enable RLS.
alter table public.documents enable row level security;
alter table public.document_shares enable row level security;

-- 3. Helper functions (SECURITY DEFINER so policies don't recurse into each other's RLS).
create or replace function public.has_document_share(p_document_id int, p_need_edit boolean)
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
      and s.user_id = (select auth.uid())
      and (not p_need_edit or s.can_edit)
  );
$$;

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

revoke execute on function public.has_document_share(int, boolean) from public;
revoke execute on function public.is_document_owner(int) from public;
grant execute on function public.has_document_share(int, boolean) to authenticated;
grant execute on function public.is_document_owner(int) to authenticated;

-- 4. Guard trigger: RLS cannot restrict individual columns per row, so enforce
--    "only the owner may change owner_id" and "id is immutable" here.
create or replace function public.documents_guard_update()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if new.id is distinct from old.id then
    raise exception 'document id cannot be changed';
  end if;

  if auth.uid() is not null
     and old.owner_id is distinct from auth.uid()
     and new.owner_id is distinct from old.owner_id then
    raise exception 'only the owner can change the document owner';
  end if;

  return new;
end;
$$;

drop trigger if exists documents_guard_update on public.documents;
create trigger documents_guard_update
  before update on public.documents
  for each row execute function public.documents_guard_update();

-- 5. Policies: public.documents
drop policy if exists documents_select on public.documents;
create policy documents_select on public.documents
  for select to authenticated
  using (
    owner_id = (select auth.uid())
    or public.has_document_share(id, false)
  );

drop policy if exists documents_insert on public.documents;
create policy documents_insert on public.documents
  for insert to authenticated
  with check (owner_id = (select auth.uid()));

drop policy if exists documents_update on public.documents;
create policy documents_update on public.documents
  for update to authenticated
  using (
    owner_id = (select auth.uid())
    or public.has_document_share(id, true)
  )
  with check (true);  -- row targeting is limited by USING; owner/id rules enforced by trigger

drop policy if exists documents_delete on public.documents;
create policy documents_delete on public.documents
  for delete to authenticated
  using (owner_id = (select auth.uid()));

-- 6. Policies: public.document_shares (owner-only management)
drop policy if exists document_shares_select on public.document_shares;
create policy document_shares_select on public.document_shares
  for select to authenticated
  using (public.is_document_owner(document_id));

drop policy if exists document_shares_insert on public.document_shares;
create policy document_shares_insert on public.document_shares
  for insert to authenticated
  with check (public.is_document_owner(document_id));

drop policy if exists document_shares_update on public.document_shares;
create policy document_shares_update on public.document_shares
  for update to authenticated
  using (public.is_document_owner(document_id))
  with check (public.is_document_owner(document_id));

drop policy if exists document_shares_delete on public.document_shares;
create policy document_shares_delete on public.document_shares
  for delete to authenticated
  using (public.is_document_owner(document_id));
