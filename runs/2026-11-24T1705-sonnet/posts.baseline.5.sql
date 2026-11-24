alter table public.posts enable row level security;

-- Remove default broad grants; grant only what is needed.
revoke all on public.posts from anon, authenticated;

grant select on public.posts to anon, authenticated;
grant insert, update, delete on public.posts to authenticated;

-- Read: anyone can read published posts.
create policy "Anyone can read published posts"
  on public.posts
  for select
  to anon, authenticated
  using (published = true);

-- Read: authors can read their own drafts (and own posts generally).
create policy "Authors can read own posts"
  on public.posts
  for select
  to authenticated
  using (author_id = (select auth.uid()));

-- Write: signed-in users can insert only as themselves.
create policy "Authors can insert own posts"
  on public.posts
  for insert
  to authenticated
  with check (author_id = (select auth.uid()));

-- Write: authors can update only their own posts, and cannot reassign them.
create policy "Authors can update own posts"
  on public.posts
  for update
  to authenticated
  using (author_id = (select auth.uid()))
  with check (author_id = (select auth.uid()));

-- Write: authors can delete only their own posts.
create policy "Authors can delete own posts"
  on public.posts
  for delete
  to authenticated
  using (author_id = (select auth.uid()));
