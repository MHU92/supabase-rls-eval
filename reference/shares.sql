-- Lookups across the two tables go through security definer functions to avoid recursive policies.
create function public.document_owner(d int) returns uuid language sql stable security definer set search_path = '' as $$
  select owner_id from public.documents where id = d
$$;
create function public.shared_with_me(d int, need_edit boolean) returns boolean language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.document_shares s
                 where s.document_id = d and s.user_id = (select auth.uid()) and (s.can_edit or not need_edit))
$$;
revoke execute on function public.document_owner(int), public.shared_with_me(int, boolean) from anon;

alter table public.documents enable row level security;
alter table public.document_shares enable row level security;
revoke all on public.documents, public.document_shares from anon;

create policy "documents: owner or shared reads" on public.documents for select to authenticated
  using ((select auth.uid()) = owner_id or public.shared_with_me(id, false));
create policy "documents: create own" on public.documents for insert to authenticated with check ((select auth.uid()) = owner_id);
-- Nobody changes the owner through an update: the check compares the new owner_id with the stored one.
-- (My first version checked "auth.uid() = owner_id" on the new row, so an editor could make themselves owner.
-- The check "editor carol takes ownership" caught it.)
create policy "documents: owner or editor updates" on public.documents for update to authenticated
  using ((select auth.uid()) = owner_id or public.shared_with_me(id, true))
  with check (owner_id = public.document_owner(id) and ((select auth.uid()) = owner_id or public.shared_with_me(id, true)));
create policy "documents: owner deletes" on public.documents for delete to authenticated using ((select auth.uid()) = owner_id);

create policy "shares: owner or recipient reads" on public.document_shares for select to authenticated
  using ((select auth.uid()) = user_id or public.document_owner(document_id) = (select auth.uid()));
create policy "shares: owner adds" on public.document_shares for insert to authenticated
  with check (public.document_owner(document_id) = (select auth.uid()));
create policy "shares: owner changes" on public.document_shares for update to authenticated
  using (public.document_owner(document_id) = (select auth.uid())) with check (public.document_owner(document_id) = (select auth.uid()));
create policy "shares: owner removes" on public.document_shares for delete to authenticated
  using (public.document_owner(document_id) = (select auth.uid()));
