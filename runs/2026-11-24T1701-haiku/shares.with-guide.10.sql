-- Migration: document sharing via RLS
-- Owners have full access to their documents. Shared users can read,
-- and can update title/content when can_edit is true. Only owners
-- insert, delete, or change sharing.

alter table public.documents enable row level security;
alter table public.document_shares enable row level security;

revoke all on table public.documents from anon, authenticated;
revoke all on table public.document_shares from anon, authenticated;

grant select, insert, update, delete on table public.documents to authenticated;
grant select, insert, update, delete on table public.document_shares to authenticated;

create index if not exists document_shares_user_id_idx
  on public.document_shares using btree (user_id);

-- documents: owner full access
create policy "Owners manage their documents"
on public.documents for all
to authenticated
using ( (select auth.uid()) = owner_id )
with check ( (select auth.uid()) = owner_id );

-- documents: shared users can read
create policy "Shared users read documents"
on public.documents for select
to authenticated
using (
  exists (
    select 1 from public.document_shares s
    where s.document_id = documents.id
      and s.user_id = (select auth.uid())
  )
);

-- documents: shared editors can update title/content (not owner)
create policy "Shared editors update documents"
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
  owner_id = (select d.owner_id from public.documents d where d.id = documents.id)
  and exists (
    select 1 from public.document_shares s
    where s.document_id = documents.id
      and s.user_id = (select auth.uid())
      and s.can_edit
  )
);

-- document_shares: owners manage sharing
create policy "Owners manage shares"
on public.document_shares for all
to authenticated
using (
  exists (
    select 1 from public.documents d
    where d.id = document_shares.document_id
      and d.owner_id = (select auth.uid())
  )
)
with check (
  exists (
    select 1 from public.documents d
    where d.id = document_shares.document_id
      and d.owner_id = (select auth.uid())
  )
);

-- document_shares: users can see their own share rows
create policy "Users read their own shares"
on public.document_shares for select
to authenticated
using ( (select auth.uid()) = user_id );
