alter table public.notes enable row level security;
revoke all on public.notes from anon;
create policy "notes: read own" on public.notes for select to authenticated using ((select auth.uid()) = user_id);
create policy "notes: create own" on public.notes for insert to authenticated with check ((select auth.uid()) = user_id);
create policy "notes: edit own" on public.notes for update to authenticated
  using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy "notes: delete own" on public.notes for delete to authenticated using ((select auth.uid()) = user_id);
