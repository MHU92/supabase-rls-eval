-- Helper functions in a non-exposed schema. They run as owner so the policies on
-- documents and document_shares can read each other's table without recursion.
create schema if not exists private;

create or replace function private.owns_document(p_document_id int)
returns boolean
language sql
security definer
stable
set search_path = ''
as $$
  select exists (
    select 1 from public.documents d
    where d.id = p_document_id
      and d.owner_id = (select auth.uid())
  );
$$;

create or replace function private.document_shared_with_me(p_document_id int, p_need_edit boolean)
returns boolean
language sql
security definer
stable
set search_path = ''
as $$
  select exists (
    select 1 from public.document_shares s
    where s.document_id = p_document_id
      and s.user_id = (select auth.uid())
      and (not p_need_edit or s.can_edit)
  );
$$;

revoke execute on function private.owns_document(int) from public, anon;
revoke execute on function private.document_shared_with_me(int, boolean) from public, anon;
grant usage on schema private to authenticated;
grant execute on function private.owns_document(int) to authenticated;
grant execute on function private.document_shared_with_me(int, boolean) to authenticated;

-- Indexes for policy filter columns
create index if not exists documents_owner_id_idx on public.documents using btree (owner_id);
create index if not exists document_shares_user_id_idx on public.document_shares using btree (user_id);

-- documents
alter table public.documents enable row level security;
revoke all on table public.documents from anon, authenticated;
grant select, insert, delete on table public.documents to authenticated;
-- Column-level update grant: nobody can change owner_id (or id) through the API.
grant update (title, content) on table public.documents to authenticated;

create policy "Owners and shared users can read documents"
on public.documents for select
to authenticated
using (
  owner_id = (select auth.uid())
  or (select private.document_shared_with_me(id, false))
);

create policy "Users can create their own documents"
on public.documents for insert
to authenticated
with check ( owner_id = (select auth.uid()) );

create policy "Owners can update their documents"
on public.documents for update
to authenticated
using ( owner_id = (select auth.uid()) )
with check ( owner_id = (select auth.uid()) );

create policy "Editors can update shared documents"
on public.documents for update
to authenticated
using ( (select private.document_shared_with_me(id, true)) )
with check ( (select private.document_shared_with_me(id, true)) );

create policy "Owners can delete their documents"
on public.documents for delete
to authenticated
using ( owner_id = (select auth.uid()) );

-- document_shares
alter table public.document_shares enable row level security;
revoke all on table public.document_shares from anon, authenticated;
grant select, insert, delete on table public.document_shares to authenticated;
grant update (can_edit) on table public.document_shares to authenticated;

create policy "Owners and recipients can read shares"
on public.document_shares for select
to authenticated
using (
  user_id = (select auth.uid())
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
