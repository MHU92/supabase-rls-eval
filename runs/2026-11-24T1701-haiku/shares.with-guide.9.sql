-- Access rule for public.documents and public.document_shares.
-- Owners do everything. Shared users can read, and edit when can_edit is true.
-- Editors cannot change owner_id or id, delete documents, or change sharing.

-- 1. Grants: drop Supabase's default grants for the client roles, then grant back only what the policies allow.
revoke all on table public.documents from anon, authenticated;
revoke all on table public.document_shares from anon, authenticated;
grant select, insert, update, delete on table public.documents to authenticated;
grant select, insert, update, delete on table public.document_shares to authenticated;

-- 2. Helper functions. They run as their owner (postgres, bypassrls), so the policies
--    on documents and document_shares do not re-enter each other (no recursion).
create schema if not exists private;

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
  )
$$;

create or replace function private.can_read_document(doc_id int)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select private.is_document_owner(doc_id) or exists (
    select 1 from public.document_shares s
    where s.document_id = doc_id and s.user_id = (select auth.uid())
  )
$$;

create or replace function private.can_edit_document(doc_id int)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select private.is_document_owner(doc_id) or exists (
    select 1 from public.document_shares s
    where s.document_id = doc_id
      and s.user_id = (select auth.uid())
      and s.can_edit
  )
$$;

revoke execute on function private.is_document_owner(int) from public;
revoke execute on function private.can_read_document(int) from public;
revoke execute on function private.can_edit_document(int) from public;
grant usage on schema private to authenticated;
grant execute on function private.is_document_owner(int) to authenticated;
grant execute on function private.can_read_document(int) to authenticated;
grant execute on function private.can_edit_document(int) to authenticated;

-- 3. Column guard. A row policy cannot tell which columns changed, so a trigger
--    stops non-owners from changing id or owner_id. Editors may change title and content only.
create or replace function private.guard_document_update()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if (new.id is distinct from old.id or new.owner_id is distinct from old.owner_id)
     and old.owner_id is distinct from (select auth.uid()) then
    raise exception 'only the owner can change id or owner_id'
      using errcode = '42501';
  end if;
  return new;
end;
$$;

drop trigger if exists guard_document_update on public.documents;
create trigger guard_document_update
before update on public.documents
for each row execute function private.guard_document_update();

-- 4. Enable RLS.
alter table public.documents enable row level security;
alter table public.document_shares enable row level security;

-- 5. Policies on documents.
create policy "documents_select_owner_or_shared"
on public.documents for select
to authenticated
using ( (select private.can_read_document(id)) );

create policy "documents_insert_as_owner"
on public.documents for insert
to authenticated
with check ( owner_id = (select auth.uid()) );

create policy "documents_update_owner_or_editor"
on public.documents for update
to authenticated
using ( (select private.can_edit_document(id)) )
with check ( (select private.can_edit_document(id)) );

create policy "documents_delete_owner"
on public.documents for delete
to authenticated
using ( (select private.is_document_owner(id)) );

-- 6. Policies on document_shares. Only the document owner manages sharing.
create policy "shares_select_owner"
on public.document_shares for select
to authenticated
using ( (select private.is_document_owner(document_id)) );

create policy "shares_insert_owner"
on public.document_shares for insert
to authenticated
with check ( (select private.is_document_owner(document_id)) );

create policy "shares_update_owner"
on public.document_shares for update
to authenticated
using ( (select private.is_document_owner(document_id)) )
with check ( (select private.is_document_owner(document_id)) );

create policy "shares_delete_owner"
on public.document_shares for delete
to authenticated
using ( (select private.is_document_owner(document_id)) );

-- 7. Indexes on the columns the policies filter on.
create index if not exists documents_owner_id_idx on public.documents (owner_id);
create index if not exists document_shares_user_id_idx on public.document_shares (user_id);
