-- Enable RLS on the posts table
alter table public.posts enable row level security;
alter table public.posts force row level security;

-- Tighten default grants: anon may only read; authenticated may read/write
revoke all on table public.posts from anon, authenticated;
grant select on table public.posts to anon, authenticated;
grant insert, update, delete on table public.posts to authenticated;

-- Read: anyone can read published posts
create policy "Published posts are readable by anyone"
  on public.posts
  for select
  to anon, authenticated
  using (published = true);

-- Read: authors can read their own drafts (and own posts generally)
create policy "Authors can read their own posts"
  on public.posts
  for select
  to authenticated
  using (author_id = (select auth.uid()));

-- Write: signed-in users can insert posts only as themselves
create policy "Authenticated users can insert their own posts"
  on public.posts
  for insert
  to authenticated
  with check (author_id = (select auth.uid()));

-- Write: authors can update only their own posts, and cannot reassign them
create policy "Authors can update their own posts"
  on public.posts
  for update
  to authenticated
  using (author_id = (select auth.uid()))
  with check (author_id = (select auth.uid()));

-- Write: authors can delete only their own posts
create policy "Authors can delete their own posts"
  on public.posts
  for delete
  to authenticated
  using (author_id = (select auth.uid()));
