-- Migration: RLS for public.posts
-- Access rule:
--   * anon + authenticated: read published posts
--   * authenticated: read own drafts
--   * authenticated: insert only as self (author_id = auth.uid())
--   * authenticated: update/delete only own posts
--   * anon: no writes

-- 1. Enable RLS
alter table public.posts enable row level security;

-- 2. Revoke default grants, then grant back only what is needed
revoke all on table public.posts from anon, authenticated;
grant select on table public.posts to anon;
grant select, insert, update, delete on table public.posts to authenticated;

-- 3. Indexes for policy filter columns
create index if not exists posts_author_id_idx on public.posts using btree (author_id);

-- 4. Policies (one per operation, all scoped to explicit roles)

-- SELECT: published posts for everyone; drafts for their author
create policy "posts_select_published_or_own"
on public.posts for select
to anon, authenticated
using (
  published
  or (
    (select auth.uid()) is not null
    and (select auth.uid()) = author_id
  )
);

-- INSERT: signed-in users may only create posts as themselves
create policy "posts_insert_own"
on public.posts for insert
to authenticated
with check ( (select auth.uid()) = author_id );

-- UPDATE: only own posts, and the row must remain owned by the caller
create policy "posts_update_own"
on public.posts for update
to authenticated
using ( (select auth.uid()) = author_id )
with check ( (select auth.uid()) = author_id );

-- DELETE: only own posts
create policy "posts_delete_own"
on public.posts for delete
to authenticated
using ( (select auth.uid()) = author_id );
