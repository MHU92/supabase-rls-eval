-- Migration: document sharing via RLS
-- Owners have full control; sharees can read, and edit title/content if can_edit is true.
-- Ownership, sharing, and deletion stay with the owner only.

alter table public.documents enable row level security;
alter table public.document_shares enable row level security;

revoke all on table public.documents from anon, authenticated;
revoke all on table public.document_shares from anon, authenticated;

-- Column-level UPDATE restriction: only title and content may be changed by authenticated users.
grant select, insert, delete on table public.documents to authenticated;
grant update (title, content) on table public.documents to authenticated;

grant select, insert, update, delete on table public.document_shares to authenticated;

create index if not exists document_shares_user_id_idx
  on public.document_shares using btree (user_id);

-- Documents: read by owner or any sharee.
create policy "documents_select_owner_or_shared"
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

-- Documents: only the owner can create, and only as themselves.
create policy "documents_insert_owner"
on public.documents for insert
to authenticated
with check ( (select auth.uid()) = owner_id );

-- Documents: owner can update anything; editing sharees can update title/content.
-- Owner_id cannot be changed by sharees (enforced via column grant and with check).
create policy "documents_update_owner_or_editor"
on public.documents for update
to authenticated
using (
  (select auth.uid()) = owner_id
  or exists (
    select 1 from public.document_shares s
    where s.document_id = documents.id
      and s.user_id = (select auth.uid())
      and s.can_edit
  )
)
with check (
  (select auth.uid()) = owner_id
  or exists (
    select 1 from public.document_shares s
    where s.document_id = documents.id
      and s.user_id = (select auth.uid())
      and s.can_edit
  )
);

-- Documents: only the owner can delete.
create policy "documents_delete_owner"
on public.documents for delete
to authenticated
using ( (select auth.uid()) = owner_id );

-- Shares: only the owner manages sharing for their documents.
create policy "shares_owner_all"
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

-- Shares: a sharee can read their own share row.
create policy "shares_select_self"
on public.document_shares for select
to authenticated
using ( (select auth.uid()) = user_id );

-- Index for the documents policies that filter on owner_id.
create index if not exists documents_owner_id_idx
  on public.documents using btree (owner_id);
