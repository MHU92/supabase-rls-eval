-- Enable RLS and restrict the table to the minimum access rule.
alter table public.posts enable row level security;
alter table public.posts force row level security;

-- Remove Supabase's default broad grants so only the policies below apply.
revoke all on public.posts from anon, authenticated;

-- Read: anyone may read published posts; authors may read their own drafts.
grant select on public.posts to anon, authenticated;
create policy posts_select
  on public.posts
  for select
  to anon, authenticated
  using (
    published = true
    or (select auth.uid()) = author_id
  );

-- Insert: signed-in users may only insert posts authored as themselves.
grant insert on public.posts to authenticated;
create policy posts_insert
  on public.posts
  for insert
  to authenticated
  with check (
    (select auth.uid()) = author_id
  );

-- Update: signed-in users may only edit their own posts, and may not reassign author_id to someone else.
grant update on public.posts to authenticated;
create policy posts_update
  on public.posts
  for update
  to authenticated
  using (
    (select auth.uid()) = author_id
  )
  with check (
    (select auth.uid()) = author_id
  );

-- Delete: signed-in users may only delete their own posts.
grant delete on public.posts to authenticated;
create policy posts_delete
  on public.posts
  for delete
  to authenticated
  using (
    (select auth.uid()) = author_id
  );
