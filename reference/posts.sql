alter table public.posts enable row level security;
revoke insert, update, delete, truncate on public.posts from anon;
create policy "posts: published for everyone" on public.posts for select to anon, authenticated using (published);
create policy "posts: authors read drafts" on public.posts for select to authenticated using ((select auth.uid()) = author_id);
create policy "posts: write as yourself" on public.posts for insert to authenticated with check ((select auth.uid()) = author_id);
create policy "posts: edit own" on public.posts for update to authenticated
  using ((select auth.uid()) = author_id) with check ((select auth.uid()) = author_id);
create policy "posts: delete own" on public.posts for delete to authenticated using ((select auth.uid()) = author_id);
