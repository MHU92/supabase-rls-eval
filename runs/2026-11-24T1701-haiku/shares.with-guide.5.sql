-- Migration: document sharing RLS
-- Owners have full control; shared users read, and edit when can_edit is true.
-- Shared users never change owner_id, delete, or touch document_shares.

-- 1. Enable RLS and reset grants (existing tables still carry default grants)
alter table public.documents enable row level security;
alter table public.document_shares enable row level security;

revoke all on table public.documents from anon, authenticated;
revoke all on table public.document_shares from anon, authenticated;

grant select, insert, update, delete on table public.documents to authenticated;
grant select, insert, update, delete on table public.document_shares to authenticated;

-- 2. Indexes for policy filters (user_id is not the leading column of the PK)
create index if not exists document_shares_user_id_idx
  on public.document_shares using btree (user_id);

-- 3. Helper functions: break the policy recursion between the two tables.
--    Both run as owner (postgres, bypassrls) with a pinned search_path.
create schema if not exists private;

create or replace function private.owned_document_ids()
returns setof int
language sql
security definer
set search_path = ''
stable
as $$
  select id from public.documents where owner_id = (select auth.uid())
$$;

create or replace function private.shared_document_ids(p_editable_only boolean)
returns setof int
language sql
security definer
set search_path = ''
stable
as $$
  select document_id from public.document_shares
  where user_id = (select auth.uid())
    and (not p_editable_only or can_edit)
$$;

revoke execute on function private.owned_document_ids() from public;
revoke execute on function private.shared_document_ids(boolean) from public;
grant usage on schema private to authenticated;
grant execute on function private.owned_document_ids() to authenticated;
grant execute on function private.shared_document_ids(boolean) to authenticated;

-- 4. documents policies
create policy "Owners manage their documents"
on public.documents for all
to authenticated
using ( owner_id = (select auth.uid()) )
with check ( owner_id = (select auth.uid()) );

create policy "Shared users read documents"
on public.documents for select
to authenticated
using ( id in (select private.shared_document_ids(false)) );

create policy "Editors update shared documents"
on public.documents for update
to authenticated
using ( id in (select private.shared_document_ids(true)) )
with check ( id in (select private.shared_document_ids(true)) );

-- 5. document_shares policies: only the owner of the document manages sharing
create policy "Owners read their document shares"
on public.document_shares for select
to authenticated
using ( document_id in (select private.owned_document_ids()) );

create policy "Owners add shares"
on public.document_shares for insert
to authenticated
with check ( document_id in (select private.owned_document_ids()) );

create policy "Owners change shares"
on public.document_shares for update
to authenticated
using ( document_id in (select private.owned_document_ids()) )
with check ( document_id in (select private.owned_document_ids()) );

create policy "Owners remove shares"
on public.document_shares for delete
to authenticated
using ( document_id in (select private.owned_document_ids()) );
