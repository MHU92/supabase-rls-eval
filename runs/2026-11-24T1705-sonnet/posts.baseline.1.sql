-- Enable RLS on the posts table
alter table public.posts enable row level security;

-- Tighten default grants: anon may only read; authenticated may read and write
revoke all on public.posts from anon, authenticated;
grant select on public.posts to anon, authenticated;
grant insert, update, delete on public.posts to authenticated;

-- Read: published posts are visible to everyone
create policy "Published posts are readable by anyone"
  on public.posts
  for select
  to anon, authenticated
  using (published = true);

-- Read: authors can see their own drafts (and their own posts generally)
create policy "Authors can read their own posts"
  on public.posts
  for select
  to authenticated
  using ((select auth.uid()) = author_id);

-- Insert: signed-in users may create posts only as themselves
create policy "Authors can insert their own posts"
  on public.posts
  for insert
  to authenticated
  with check ((select auth.uid()) = author_id);

-- Update: authors may edit only their own posts, and cannot reassign ownership
create policy "Authors can update their own posts"
  on public.posts
  for update
  to authenticated
  using ((select auth.uid()) = author_id)
  with check ((select auth.uid()) = author_id);

-- Delete: authors may delete only their own posts
create policy "Authors can delete their own posts"
  on public.posts
  for delete
  to authenticated
  using ((select auth.uid()) = author_id);
