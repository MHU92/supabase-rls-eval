begin;

-- Enable RLS so row access is governed by the policies below.
alter table public.documents enable row level security;
alter table public.document_shares enable row level security;

-- Replace Supabase's default grants: anon gets nothing; authenticated keeps table
-- privileges, and RLS policies decide which rows each user can touch.
revoke all on public.documents from anon, authenticated;
revoke all on public.document_shares from anon, authenticated;
grant select, insert, update, delete on public.documents to authenticated;
grant select, insert, update, delete on public.document_shares to authenticated;

-- Helper functions run as definer so policies don't recurse between the two tables.
create or replace function public.is_document_owner(doc_id int)
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

create or replace function public.can_read_document(doc_id int)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select public.is_document_owner(doc_id)
      or exists (
        select 1 from public.document_shares s
        where s.document_id = doc_id and s.user_id = (select auth.uid())
      );
$$;

create or replace function public.can_edit_document(doc_id int)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select public.is_document_owner(doc_id)
      or exists (
        select 1 from public.document_shares s
        where s.document_id = doc_id
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

-- Column guard: editors may change title/content only; ownership and id are protected.
create or replace function public.documents_guard_columns()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if new.id is distinct from old.id then
    raise exception 'document id cannot be changed';
  end if;

  if new.owner_id is distinct from old.owner_id
     and (select auth.uid()) is not null
     and (select auth.uid()) is distinct from old.owner_id then
    raise exception 'only the owner can change document ownership';
  end if;

  return new;
end;
$$;

revoke execute on function public.documents_guard_columns() from public, anon, authenticated;

create trigger documents_guard_columns
before update on public.documents
for each row execute function public.documents_guard_columns();

-- documents policies
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

-- document_shares policies: only the document owner manages sharing
create policy document_shares_owner_all on public.document_shares
for all to authenticated
using (public.is_document_owner(document_id))
with check (public.is_document_owner(document_id));

commit;
