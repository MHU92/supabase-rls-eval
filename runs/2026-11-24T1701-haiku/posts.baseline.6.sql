begin;

alter table public.posts enable row level security;

-- Drop Supabase's default broad grants, then re-grant only what the rule needs.
revoke all on public.posts from anon, authenticated;
grant select on public.posts to anon, authenticated;
grant insert, update, delete on public.posts to authenticated;

-- Read: anyone sees published posts; authors also see their own drafts.
create policy posts_select_published_or_own
  on public.posts
  for select
  to anon, authenticated
  using (
    published = true
    or (select auth.uid()) = author_id
  );

-- Write: signed-in users may insert only as themselves.
create policy posts_insert_own
  on public.posts
  for insert
  to authenticated
  with check (
    (select auth.uid()) = author_id
  );

-- Edit: only the author may update, and the row may not be reassigned to someone else.
create policy posts_update_own
  on public.posts
  for update
  to authenticated
  using (
    (select auth.uid()) = author_id
  )
  with check (
    (select auth.uid()) = author_id
  );

-- Delete: only the author may delete their own posts.
create policy posts_delete_own
  on public.posts
  for delete
  to authenticated
  using (
    (select auth.uid()) = author_id
  );

commit;
