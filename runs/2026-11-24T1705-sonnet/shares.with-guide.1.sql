-- Enable RLS and lock down grants
alter table public.documents enable row level security;
alter table public.document_shares enable row level security;

revoke all on table public.documents from anon, authenticated;
revoke all on table public.document_shares from anon, authenticated;

grant select, insert, delete on table public.documents to authenticated;
-- Column-level update grant: the id can never be changed by clients.
grant update (owner_id, title, content) on table public.documents to authenticated;

grant select, insert, update, delete on table public.document_shares to authenticated;

-- Indexes for policy filter columns
create index if not exists documents_owner_id_idx on public.documents (owner_id);
create index if not exists document_shares_user_id_idx on public.document_shares (user_id);

-- Helper functions (security definer) to avoid recursive policies
create schema if not exists private;

create or replace function private.owned_document_ids()
returns setof int
language sql
security definer
set search_path = ''
stable
as $$
  select id from public.documents
  where owner_id = (select auth.uid())
$$;

create or replace function private.shared_document_ids()
returns setof int
language sql
security definer
set search_path = ''
stable
as $$
  select document_id from public.document_shares
  where user_id = (select auth.uid())
$$;

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

revoke execute on function private.owned_document_ids() from public;
revoke execute on function private.shared_document_ids() from public;
revoke execute on function private.editable_document_ids() from public;
grant usage on schema private to authenticated;
grant execute on function private.owned_document_ids() to authenticated;
grant execute on function private.shared_document_ids() to authenticated;
grant execute on function private.editable_document_ids() to authenticated;

-- Only the current owner may change owner_id (editors may not)
create or replace function private.protect_document_owner()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if new.owner_id is distinct from old.owner_id
     and old.owner_id is distinct from (select auth.uid()) then
    raise exception 'only the owner can change the owner of a document'
      using errcode = '42501';
  end if;
  return new;
end;
$$;

drop trigger if exists protect_document_owner on public.documents;
create trigger protect_document_owner
before update on public.documents
for each row execute function private.protect_document_owner();

-- documents policies
create policy "Owners and shared users can read documents"
on public.documents for select
to authenticated
using (
  owner_id = (select auth.uid())
  or id in (select private.shared_document_ids())
);

create policy "Users can create their own documents"
on public.documents for insert
to authenticated
with check ( owner_id = (select auth.uid()) );

create policy "Owners can update their documents"
on public.documents for update
to authenticated
using ( owner_id = (select auth.uid()) )
with check ( true );

create policy "Editors can update shared documents"
on public.documents for update
to authenticated
using ( id in (select private.editable_document_ids()) )
with check ( id in (select private.editable_document_ids()) );

create policy "Owners can delete their documents"
on public.documents for delete
to authenticated
using ( owner_id = (select auth.uid()) );

-- document_shares policies
create policy "Owners and recipients can read shares"
on public.document_shares for select
to authenticated
using (
  user_id = (select auth.uid())
  or document_id in (select private.owned_document_ids())
);

create policy "Owners can create shares"
on public.document_shares for insert
to authenticated
with check ( document_id in (select private.owned_document_ids()) );

create policy "Owners can update shares"
on public.document_shares for update
to authenticated
using ( document_id in (select private.owned_document_ids()) )
with check ( document_id in (select private.owned_document_ids()) );

create policy "Owners can delete shares"
on public.document_shares for delete
to authenticated
using ( document_id in (select private.owned_document_ids()) );
