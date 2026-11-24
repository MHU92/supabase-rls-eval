-- Migration: RLS for public.posts
-- Access rule:
--   * anon and authenticated may read published posts.
--   * authenticated users may read their own drafts.
--   * authenticated users may insert only rows where author_id = auth.uid().
--   * authenticated users may update/delete only their own posts.
--   * anon cannot write.

alter table public.posts enable row level security;

-- Remove default grants from client roles, then grant back only what is needed.
revoke all on table public.posts from anon, authenticated;
grant select on table public.posts to anon, authenticated;
grant insert, update, delete on table public.posts to authenticated;

-- Index the column the policies filter on.
create index if not exists posts_author_id_idx on public.posts using btree (author_id);

-- SELECT: published posts for everyone, plus own drafts for signed-in users.
create policy "Anyone can read published posts"
on public.posts for select
to anon, authenticated
using ( published = true );

create policy "Authors can read their own drafts"
on public.posts for select
to authenticated
using ( (select auth.uid()) = author_id );

-- INSERT: signed-in users may only create posts authored by themselves.
create policy "Authors can create their own posts"
on public.posts for insert
to authenticated
with check ( (select auth.uid()) = author_id );

-- UPDATE: only the author may update, and the row must remain theirs.
create policy "Authors can update their own posts"
on public.posts for update
to authenticated
using ( (select auth.uid()) = author_id )
with check ( (select auth.uid()) = author_id );

-- DELETE: only the author may delete.
create policy "Authors can delete their own posts"
on public.posts for delete
to authenticated
using ( (select auth.uid()) = author_id );
