-- Migration: document access via ownership and sharing
-- Owners: full access. Shared users: select; update title/content only if can_edit.
-- Shared users never delete or change ownership/sharing. Owners manage shares.

begin;

-- 1. Enable RLS and reset grants on both tables
alter table public.documents enable row level security;
alter table public.document_shares enable row level security;

revoke all on table public.documents from anon, authenticated;
revoke all on table public.document_shares from anon, authenticated;

-- Grant only what the app needs. Column-level update restricts changes to title and content.
grant select, insert, delete on table public.documents to authenticated;
grant update (title, content) on table public.documents to authenticated;
grant select, insert, update, delete on table public.document_shares to authenticated;

-- 2. Indexes for policy filters
create index if not exists document_shares_user_id_idx
  on public.document_shares using btree (user_id);

-- 3. Helper: documents the caller may edit via a share (security definer, pinned search_path)
create schema if not exists private;

create or replace function private.editable_document_ids()
returns setof int
language sql
security definer
set search_path = ''
stable
as $$
  select document_id from public.document_shares
  where user_id = (select auth.uid()) and can_edit
$$;

create or replace function private.readable_document_ids()
returns setof int
language sql
security definer
set search_path = ''
stable
as $$
  select document_id from public.document_shares
  where user_id = (select auth.uid())
$$;

revoke execute on function private.editable_document_ids() from public;
revoke execute on function private.readable_document_ids() from public;
grant usage on schema private to authenticated;
grant execute on function private.editable_document_ids() to authenticated;
grant execute on function private.readable_document_ids() to authenticated;

-- 4. documents policies
create policy "owners select their documents"
on public.documents for select
to authenticated
using ( owner_id = (select auth.uid()) or id in (select private.readable_document_ids()) );

create policy "owners insert their documents"
on public.documents for insert
to authenticated
with check ( owner_id = (select auth.uid()) );

create policy "owners or editors update documents"
on public.documents for update
to authenticated
using ( owner_id = (select auth.uid()) or id in (select private.editable_document_ids()) )
with check ( owner_id = (select auth.uid()) or id in (select private.editable_document_ids()) );

create policy "owners delete their documents"
on public.documents for delete
to authenticated
using ( owner_id = (select auth.uid()) );

-- 5. document_shares policies: only the owner manages sharing
create policy "owners select shares"
on public.document_shares for select
to authenticated
using (
  exists (
    select 1 from public.documents d
    where d.id = document_shares.document_id and d.owner_id = (select auth.uid())
  )
  or user_id = (select auth.uid())
);

create policy "owners insert shares"
on public.document_shares for insert
to authenticated
with check (
  exists (
    select 1 from public.documents d
    where d.id = document_shares.document_id and d.owner_id = (select auth.uid())
  )
);

create policy "owners update shares"
on public.document_shares for update
to authenticated
using (
  exists (
    select 1 from public.documents d
    where d.id = document_shares.document_id and d.owner_id = (select auth.uid())
  )
)
with check (
  exists (
    select 1 from public.documents d
    where d.id = document_shares.document_id and d.owner_id = (select auth.uid())
  )
);

create policy "owners delete shares"
on public.document_shares for delete
to authenticated
using (
  exists (
    select 1 from public.documents d
    where d.id = document_shares.document_id and d.owner_id = (select auth.uid())
  )
);

commit;
