-- Enable RLS and force it for the table owner as well
alter table public.posts enable row level security;
alter table public.posts force row level security;

-- Tighten default grants: Supabase grants all privileges to anon and authenticated
revoke all on table public.posts from anon, authenticated;

-- Anonymous visitors: read only (RLS limits to published rows)
grant select on table public.posts to anon;

-- Signed-in users: read, insert, update, delete (RLS limits rows)
grant select, insert, update, delete on table public.posts to authenticated;

-- Read: published posts for everyone
create policy "posts_select_published"
  on public.posts
  for select
  to anon, authenticated
  using (published = true);

-- Read: authors can see their own drafts (and own posts generally)
create policy "posts_select_own"
  on public.posts
  for select
  to authenticated
  using (author_id = (select auth.uid()));

-- Insert: only as themselves
create policy "posts_insert_own"
  on public.posts
  for insert
  to authenticated
  with check (author_id = (select auth.uid()));

-- Update: only own posts, and they must remain own
create policy "posts_update_own"
  on public.posts
  for update
  to authenticated
  using (author_id = (select auth.uid()))
  with check (author_id = (select auth.uid()));

-- Delete: only own posts
create policy "posts_delete_own"
  on public.posts
  for delete
  to authenticated
  using (author_id = (select auth.uid()));
