-- Helper functions (security definer) break the policy recursion between
-- documents and document_shares.
create schema if not exists private;
grant usage on schema private to authenticated;

create function private.owns_document(doc_id int)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.documents d
    where d.id = doc_id
      and d.owner_id = (select auth.uid())
  );
$$;

create function private.has_document_share(doc_id int, need_edit boolean)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.document_shares s
    where s.document_id = doc_id
      and s.user_id = (select auth.uid())
      and (not need_edit or s.can_edit)
  );
$$;

revoke execute on function private.owns_document(int) from public;
revoke execute on function private.has_document_share(int, boolean) from public;
grant execute on function private.owns_document(int) to authenticated;
grant execute on function private.has_document_share(int, boolean) to authenticated;

-- Indexes for columns used by policies / helper functions
create index if not exists documents_owner_id_idx on public.documents using btree (owner_id);
create index if not exists document_shares_user_id_idx on public.document_shares using btree (user_id);

-- RLS + grants
alter table public.documents enable row level security;
alter table public.document_shares enable row level security;

revoke all on table public.documents from anon, authenticated;
revoke all on table public.document_shares from anon, authenticated;

-- Column-level update grants: nobody can change id or owner_id through the API,
-- so a user with edit rights can only change title and content.
grant select, insert, delete on table public.documents to authenticated;
grant update (title, content) on table public.documents to authenticated;

grant select, insert, delete on table public.document_shares to authenticated;
grant update (can_edit) on table public.document_shares to authenticated;

-- documents policies
create policy "Owners and shared users can read documents"
on public.documents for select
to authenticated
using (
  (select auth.uid()) = owner_id
  or private.has_document_share(id, false)
);

create policy "Users can create their own documents"
on public.documents for insert
to authenticated
with check ( (select auth.uid()) = owner_id );

create policy "Owners and editors can update documents"
on public.documents for update
to authenticated
using (
  (select auth.uid()) = owner_id
  or private.has_document_share(id, true)
)
with check (
  (select auth.uid()) = owner_id
  or private.has_document_share(id, true)
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
  or private.owns_document(document_id)
);

create policy "Owners can create shares"
on public.document_shares for insert
to authenticated
with check ( private.owns_document(document_id) );

create policy "Owners can update shares"
on public.document_shares for update
to authenticated
using ( private.owns_document(document_id) )
with check ( private.owns_document(document_id) );

create policy "Owners can delete shares"
on public.document_shares for delete
to authenticated
using ( private.owns_document(document_id) );
