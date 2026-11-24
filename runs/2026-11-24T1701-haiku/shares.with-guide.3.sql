-- Migration: document access via ownership and sharing
-- Owners: full control. Shared users: read; read+write title/content if can_edit.
-- Shared users never delete, never change owner_id, never change sharing.

begin;

-- Indexes for policy lookups
create index if not exists document_shares_user_id_idx
  on public.document_shares using btree (user_id);

-- Enable RLS and reset grants
alter table public.documents enable row level security;
alter table public.document_shares enable row level security;

revoke all on table public.documents from anon, authenticated;
revoke all on table public.document_shares from anon, authenticated;

grant select, insert, update, delete on table public.documents to authenticated;
grant select, insert, update, delete on table public.document_shares to authenticated;

-- Helper: document ids the caller can read via a share (runs as owner, avoids recursion)
create schema if not exists private;

create or replace function private.shared_document_ids(read_only boolean default false)
returns setof int
language sql
security definer
stable
set search_path = ''
as $$
  select document_id
  from public.document_shares
  where user_id = (select auth.uid())
    and (not read_only or can_edit = true)
$$;

create or replace function private.owned_document_ids()
returns setof int
language sql
security definer
stable
set search_path = ''
as $$
  select id from public.documents
  where owner_id = (select auth.uid())
$$;

revoke execute on function private.shared_document_ids(boolean) from public;
revoke execute on function private.owned_document_ids() from public;
grant usage on schema private to authenticated;
grant execute on function private.shared_document_ids(boolean) to authenticated;
grant execute on function private.owned_document_ids() to authenticated;

-- documents policies
create policy "owners select documents"
on public.documents for select
to authenticated
using ( owner_id = (select auth.uid()) );

create policy "shared users select documents"
on public.documents for select
to authenticated
using ( id in (select private.shared_document_ids(false)) );

create policy "owners insert documents"
on public.documents for insert
to authenticated
with check ( owner_id = (select auth.uid()) );

create policy "owners update documents"
on public.documents for update
to authenticated
using ( owner_id = (select auth.uid()) )
with check ( owner_id = (select auth.uid()) );

create policy "editors update documents"
on public.documents for update
to authenticated
using ( id in (select private.shared_document_ids(true)) )
with check ( id in (select private.shared_document_ids(true)) );

create policy "owners delete documents"
on public.documents for delete
to authenticated
using ( owner_id = (select auth.uid()) );

-- document_shares policies: only the owner manages sharing
create policy "owners select shares"
on public.document_shares for select
to authenticated
using ( document_id in (select private.owned_document_ids()) );

create policy "shared users see own share"
on public.document_shares for select
to authenticated
using ( user_id = (select auth.uid()) );

create policy "owners insert shares"
on public.document_shares for insert
to authenticated
with check ( document_id in (select private.owned_document_ids()) );

create policy "owners update shares"
on public.document_shares for update
to authenticated
using ( document_id in (select private.owned_document_ids()) )
with check ( document_id in (select private.owned_document_ids()) );

create policy "owners delete shares"
on public.document_shares for delete
to authenticated
using ( document_id in (select private.owned_document_ids()) );

commit;
