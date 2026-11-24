-- Helper functions live in a non-exposed schema. They run as their owner so the
-- policies on documents and document_shares can read each other's table
-- without recursing.
create schema if not exists private;
revoke all on schema private from public;
grant usage on schema private to authenticated;

create or replace function private.is_document_owner(p_document_id int)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.documents d
    where d.id = p_document_id
      and d.owner_id = (select auth.uid())
  );
$$;

create or replace function private.has_document_share(p_document_id int)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.document_shares s
    where s.document_id = p_document_id
      and s.user_id = (select auth.uid())
  );
$$;

create or replace function private.can_edit_document(p_document_id int)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.document_shares s
    where s.document_id = p_document_id
      and s.user_id = (select auth.uid())
      and s.can_edit
  );
$$;

revoke execute on function private.is_document_owner(int) from public;
revoke execute on function private.has_document_share(int) from public;
revoke execute on function private.can_edit_document(int) from public;
grant execute on function private.is_document_owner(int) to authenticated;
grant execute on function private.has_document_share(int) to authenticated;
grant execute on function private.can_edit_document(int) to authenticated;

-- Indexes for the columns the policies filter on.
create index if not exists documents_owner_id_idx on public.documents using btree (owner_id);
create index if not exists document_shares_user_id_idx on public.document_shares using btree (user_id);

-- Enable RLS and reset grants.
alter table public.documents enable row level security;
alter table public.document_shares enable row level security;

revoke all on table public.documents from anon, authenticated;
revoke all on table public.document_shares from anon, authenticated;

-- Column-level update grant: id and owner_id can never be changed through the
-- API, so editors cannot reassign the owner.
grant select, insert, delete on table public.documents to authenticated;
grant update (title, content) on table public.documents to authenticated;

grant select, insert, delete on table public.document_shares to authenticated;
grant update (user_id, can_edit) on table public.document_shares to authenticated;

-- documents policies
create policy "Owners and shared users can read documents"
on public.documents for select
to authenticated
using (
  owner_id = (select auth.uid())
  or (select private.has_document_share(id))
);

create policy "Users can create their own documents"
on public.documents for insert
to authenticated
with check ( owner_id = (select auth.uid()) );

create policy "Owners and editors can update documents"
on public.documents for update
to authenticated
using (
  owner_id = (select auth.uid())
  or (select private.can_edit_document(id))
)
with check (
  owner_id = (select auth.uid())
  or (select private.can_edit_document(id))
);

create policy "Owners can delete their documents"
on public.documents for delete
to authenticated
using ( owner_id = (select auth.uid()) );

-- document_shares policies
create policy "Owners see shares of their documents, users see their own"
on public.document_shares for select
to authenticated
using (
  user_id = (select auth.uid())
  or (select private.is_document_owner(document_id))
);

create policy "Owners can share their documents"
on public.document_shares for insert
to authenticated
with check ( (select private.is_document_owner(document_id)) );

create policy "Owners can change shares of their documents"
on public.document_shares for update
to authenticated
using ( (select private.is_document_owner(document_id)) )
with check ( (select private.is_document_owner(document_id)) );

create policy "Owners can remove shares of their documents"
on public.document_shares for delete
to authenticated
using ( (select private.is_document_owner(document_id)) );
