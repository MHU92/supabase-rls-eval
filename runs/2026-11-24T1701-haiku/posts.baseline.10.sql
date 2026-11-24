-- Enable RLS and force it so table owners are also subject to policies
alter table public.posts enable row level security;
alter table public.posts force row level security;

-- Remove Supabase's default broad grants for anon/authenticated, then re-grant only what is needed
revoke all on public.posts from anon, authenticated;
grant select, insert, update, delete on public.posts to authenticated;
grant select on public.posts to anon;

-- Anyone (signed in or not) can read published posts; authors can read their own drafts
create policy posts_select_published_or_own
  on public.posts
  for select
  to anon, authenticated
  using (
    published = true
    or (select auth.uid()) = author_id
  );

-- Signed-in users can insert posts only as themselves
create policy posts_insert_own
  on public.posts
  for insert
  to authenticated
  with check (
    (select auth.uid()) = author_id
  );

-- Signed-in users can update only their own posts, and cannot reassign author_id to someone else
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

-- Signed-in users can delete only their own posts
create policy posts_delete_own
  on public.posts
  for delete
  to authenticated
  using (
    (select auth.uid()) = author_id
  );
