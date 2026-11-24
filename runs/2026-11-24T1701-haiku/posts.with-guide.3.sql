-- Migration: RLS for public.posts
-- Access rule:
--   * Anyone (anon or authenticated) may read published posts.
--   * Authors may read their own drafts.
--   * Signed-in users may insert only posts where author_id = themselves.
--   * Signed-in users may update/delete only their own posts.
--   * Signed-out visitors cannot write.

begin;

-- 1. Enable RLS (no-op if already enabled; FORCE not used so table owner bypasses as usual)
alter table public.posts enable row level security;

-- 2. Remove Supabase's default grants, then grant back only what is needed.
--    anon: read only. authenticated: read/insert/update/delete.
revoke all on table public.posts from anon, authenticated;
grant select on table public.posts to anon, authenticated;
grant insert, update, delete on table public.posts to authenticated;

-- 3. Index the column the policies filter on (author_id is not the leading PK column).
create index if not exists posts_author_id_idx on public.posts using btree (author_id);

-- 4. Policies, one per operation, all scoped to explicit roles.

-- SELECT: published posts for everyone; drafts for their author.
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

-- INSERT: signed-in users, only as themselves.
create policy "posts_insert_own"
on public.posts for insert
to authenticated
with check (
  (select auth.uid()) is not null
  and (select auth.uid()) = author_id
);

-- UPDATE: only own posts; the row must remain owned by the caller.
create policy "posts_update_own"
on public.posts for update
to authenticated
using (
  (select auth.uid()) is not null
  and (select auth.uid()) = author_id
)
with check (
  (select auth.uid()) is not null
  and (select auth.uid()) = author_id
);

-- DELETE: only own posts.
create policy "posts_delete_own"
on public.posts for delete
to authenticated
using (
  (select auth.uid()) is not null
  and (select auth.uid()) = author_id
);

commit;
