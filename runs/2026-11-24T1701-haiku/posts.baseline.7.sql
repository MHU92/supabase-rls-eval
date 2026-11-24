-- Enable Row Level Security on posts
alter table public.posts enable row level security;

-- Tighten Supabase's default grants: anon may only read, authenticated gets only the DML it needs
revoke all on public.posts from anon, authenticated;
grant select on public.posts to anon, authenticated;
grant insert, update, delete on public.posts to authenticated;

-- Make the migration re-runnable
drop policy if exists posts_select_published_or_own on public.posts;
drop policy if exists posts_insert_own on public.posts;
drop policy if exists posts_update_own on public.posts;
drop policy if exists posts_delete_own on public.posts;

-- Anyone (signed in or not) reads published posts; authors also read their own drafts
create policy posts_select_published_or_own
  on public.posts
  for select
  to anon, authenticated
  using (
    published
    or author_id = (select auth.uid())
  );

-- Signed-in users may insert posts only as themselves
create policy posts_insert_own
  on public.posts
  for insert
  to authenticated
  with check (
    author_id = (select auth.uid())
  );

-- Signed-in users may update only their own posts, and cannot reassign them to someone else
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

-- Signed-in users may delete only their own posts
create policy posts_delete_own
  on public.posts
  for delete
  to authenticated
  using (
    author_id = (select auth.uid())
  );
