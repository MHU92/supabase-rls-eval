-- Enable Row Level Security on posts
alter table public.posts enable row level security;
alter table public.posts force row level security;

-- Tighten default grants: anonymous visitors may only read, never write
revoke all on public.posts from anon;
revoke all on public.posts from authenticated;
grant select on public.posts to anon;
grant select, insert, update, delete on public.posts to authenticated;

-- Read: anyone can read published posts
create policy "Published posts are readable by everyone"
  on public.posts
  for select
  to anon, authenticated
  using (published = true);

-- Read: authors can read their own drafts (and their own posts generally)
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

-- Write: authors can update only their own posts, and cannot reassign ownership
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
