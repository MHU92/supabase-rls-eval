begin;

-- Enable RLS and remove grants that bypass the access rule
alter table public.documents enable row level security;
alter table public.document_shares enable row level security;

revoke all on public.documents from anon, authenticated;
revoke all on public.document_shares from anon, authenticated;
grant select, insert, update, delete on public.documents to authenticated;
grant select, insert, update, delete on public.document_shares to authenticated;

-- Index for "documents shared with me" lookups (primary key starts with document_id)
create index if not exists document_shares_user_id_idx on public.document_shares (user_id);

-- Owner check used by document_shares policies. SECURITY DEFINER avoids RLS
-- recursion between the two tables.
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

-- Only the owner may change owner_id or id. Shared editors may change other columns.
create or replace function public.protect_document_owner()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if (select auth.uid()) is not null
     and (select auth.uid()) is distinct from old.owner_id
     and (new.owner_id is distinct from old.owner_id or new.id is distinct from old.id) then
    raise exception 'only the document owner can change owner_id or id';
  end if;
  return new;
end;
$$;

drop trigger if exists documents_protect_owner on public.documents;
create trigger documents_protect_owner
  before update on public.documents
  for each row execute function public.protect_document_owner();

-- documents policies
drop policy if exists documents_select on public.documents;
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

drop policy if exists documents_insert on public.documents;
create policy documents_insert on public.documents
  for insert to authenticated
  with check (owner_id = (select auth.uid()));

drop policy if exists documents_update_owner on public.documents;
create policy documents_update_owner on public.documents
  for update to authenticated
  using (owner_id = (select auth.uid()))
  with check (true);

drop policy if exists documents_update_editor on public.documents;
create policy documents_update_editor on public.documents
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

drop policy if exists documents_delete_owner on public.documents;
create policy documents_delete_owner on public.documents
  for delete to authenticated
  using (owner_id = (select auth.uid()));

-- document_shares policies: only the owner manages sharing
drop policy if exists document_shares_owner_all on public.document_shares;
create policy document_shares_owner_all on public.document_shares
  for all to authenticated
  using (public.is_document_owner(document_id))
  with check (public.is_document_owner(document_id));

commit;
