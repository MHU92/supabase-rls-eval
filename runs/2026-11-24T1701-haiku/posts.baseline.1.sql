-- Access rule for public.posts: public reads of published posts, author reads of own drafts,
-- signed-in writes only as self, and no writes for signed-out visitors.

alter table public.posts enable row level security;

-- Remove Supabase's default broad grants so only the intended operations remain.
revoke all on public.posts from anon, authenticated;
grant select on public.posts to anon, authenticated;
grant insert, update, delete on public.posts to authenticated;

-- Reads: anyone sees published posts; authors also see their own drafts.
create policy posts_select_published_or_own
  on public.posts
  for select
  to anon, authenticated
  using (
    published
    or author_id = (select auth.uid())
  );

-- Inserts: signed-in users may only create posts authored as themselves.
create policy posts_insert_own
  on public.posts
  for insert
  to authenticated
  with check (
    author_id = (select auth.uid())
  );

-- Updates: only the author may edit their post, and the row must remain theirs afterwards.
create policy posts_update_own
  on public.posts
  for update
  to authenticated
  using (
    author_id = (select auth.uid())
  )
  with check (
    author_id = (select auth.uid())
  );

-- Deletes: only the author may delete their post.
create policy posts_delete_own
  on public.posts
  for delete
  to authenticated
  using (
    author_id = (select auth.uid())
  );
