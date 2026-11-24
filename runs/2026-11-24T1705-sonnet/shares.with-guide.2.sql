-- Documents and sharing: owner/editor/reader access via RLS

-- Helper schema (not exposed through the Data API)
create schema if not exists private;
grant usage on schema private to authenticated;

-- Security definer helper: breaks the documents <-> document_shares policy cycle
create or replace function private.owns_document(doc_id int)
returns boolean
language sql
security definer
stable
set search_path = ''
as $$
  select exists (
    select 1 from public.documents d
    where d.id = doc_id
      and d.owner_id = (select auth.uid())
  )
$$;

revoke execute on function private.owns_document(int) from public;
grant execute on function private.owns_document(int) to authenticated;

-- Indexes for policy filter columns
create index if not exists documents_owner_id_idx
  on public.documents using btree (owner_id);
create index if not exists document_shares_user_id_idx
  on public.document_shares using btree (user_id);

-- Enable RLS
alter table public.documents enable row level security;
alter table public.document_shares enable row level security;

-- Reset grants, then grant back only what is needed
revoke all on table public.documents from anon, authenticated;
revoke all on table public.document_shares from anon, authenticated;

grant select, insert, delete on table public.documents to authenticated;
-- Column-level update: nobody can change id or owner_id (so editors cannot touch the owner)
grant update (title, content) on table public.documents to authenticated;

grant select, insert, update, delete on table public.document_shares to authenticated;

-- documents policies
create policy "Owners and shared users can read documents"
on public.documents for select
to authenticated
using (
  (select auth.uid()) = owner_id
  or exists (
    select 1 from public.document_shares s
    where s.document_id = documents.id
      and s.user_id = (select auth.uid())
  )
);

create policy "Users can create their own documents"
on public.documents for insert
to authenticated
with check ( (select auth.uid()) = owner_id );

create policy "Owners can update their documents"
on public.documents for update
to authenticated
using ( (select auth.uid()) = owner_id )
with check ( (select auth.uid()) = owner_id );

create policy "Editors can update shared documents"
on public.documents for update
to authenticated
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

create policy "Owners can delete their documents"
on public.documents for delete
to authenticated
using ( (select auth.uid()) = owner_id );

-- document_shares policies
create policy "Owners and recipients can read shares"
on public.document_shares for select
to authenticated
using (
  (select auth.uid()) = user_id
  or (select private.owns_document(document_id))
);

create policy "Owners can create shares"
on public.document_shares for insert
to authenticated
with check ( (select private.owns_document(document_id)) );

create policy "Owners can update shares"
on public.document_shares for update
to authenticated
using ( (select private.owns_document(document_id)) )
with check ( (select private.owns_document(document_id)) );

create policy "Owners can delete shares"
on public.document_shares for delete
to authenticated
using ( (select private.owns_document(document_id)) );
