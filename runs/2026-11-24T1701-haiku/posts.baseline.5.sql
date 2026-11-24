-- Enable RLS on posts (idempotent; force so the table owner is also subject to policies)
alter table public.posts enable row level security;
alter table public.posts force row level security;

-- Remove default broad grants; re-grant only what the access rule needs
revoke all on public.posts from anon, authenticated;
grant select on public.posts to anon, authenticated;
grant insert, update, delete on public.posts to authenticated;

-- Drop any existing policies so the migration is re-runnable
drop policy if exists posts_select_published_or_own on public.posts;
drop policy if exists posts_insert_as_self on public.posts;
drop policy if exists posts_update_own on public.posts;
drop policy if exists posts_delete_own on public.posts;

-- Read: anyone can read published posts; authors can read their own drafts
create policy posts_select_published_or_own
  on public.posts
  for select
  to anon, authenticated
  using (
    published
    or (select auth.uid()) = author_id
  );

-- Insert: signed-in users may only insert rows authored as themselves
create policy posts_insert_as_self
  on public.posts
  for insert
  to authenticated
  with check (
    (select auth.uid()) = author_id
  );

-- Update: only the author may update, and may not reassign author_id to someone else
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

-- Delete: only the author may delete their own posts
create policy posts_delete_own
  on public.posts
  for delete
  to authenticated
  using (
    (select auth.uid()) = author_id
  );
