-- Enable RLS and restrict grants so only the intended policies govern access.
alter table public.posts enable row level security;
alter table public.posts force row level security;

-- Supabase's default grants give anon/authenticated full access; limit them to what the rule needs.
revoke all on public.posts from anon, authenticated;
grant select on public.posts to anon, authenticated;
grant insert, update, delete on public.posts to authenticated;

-- Anyone (signed in or not) can read published posts; authors can read their own drafts.
create policy posts_select_published_or_own
  on public.posts
  for select
  to anon, authenticated
  using (
    published = true
    or (select auth.uid()) = author_id
  );

-- Signed-in users can insert posts only as themselves.
create policy posts_insert_own
  on public.posts
  for insert
  to authenticated
  with check (
    (select auth.uid()) = author_id
  );

-- Signed-in users can update only their own posts, and cannot reassign authorship to someone else.
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

-- Signed-in users can delete only their own posts.
create policy posts_delete_own
  on public.posts
  for delete
  to authenticated
  using (
    (select auth.uid()) = author_id
  );
