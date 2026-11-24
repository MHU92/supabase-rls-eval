-- Typical mistake: documents look up shares and shares look up documents, so each policy triggers the other.
alter table public.documents enable row level security;
alter table public.document_shares enable row level security;
create policy "documents: owner or shared" on public.documents for all
  using (owner_id = auth.uid() or id in (select document_id from public.document_shares where user_id = auth.uid()));
create policy "shares: owner or recipient" on public.document_shares for all
  using (user_id = auth.uid() or document_id in (select id from public.documents where owner_id = auth.uid()));
