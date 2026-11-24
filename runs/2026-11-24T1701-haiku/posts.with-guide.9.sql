-- Migration: row-level access rules for public.posts

begin;

alter table public.posts enable row level security;

-- Start from zero grants for client roles, then grant back only what the rule needs.
revoke all on table public.posts from anon, authenticated;

-- Signed-out visitors may read published posts only. No write grant.
grant select on table public.posts to anon;
-- Signed-in users may read, and write their own posts. Policies limit which rows.
grant select, insert, update, delete on table public.posts to authenticated;

-- Index the column the policies filter on.
create index if not exists posts_author_id_idx
  on public.posts using btree (author_id);

-- Anyone, signed in or not, can read published posts.
create policy "Anyone can read published posts"
on public.posts for select
to anon, authenticated
using ( published );

-- Authors can read their own drafts too.
create policy "Authors can read their own posts"
on public.posts for select
to authenticated
using ( (select auth.uid()) = author_id );

-- Signed-in users can create posts only as themselves.
create policy "Users can create their own posts"
on public.posts for insert
to authenticated
with check ( (select auth.uid()) = author_id );

-- Authors can edit only their own posts, and cannot reassign them to someone else.
create policy "Authors can update their own posts"
on public.posts for update
to authenticated
using ( (select auth.uid()) = author_id )
with check ( (select auth.uid()) = author_id );

-- Authors can delete only their own posts.
create policy "Authors can delete their own posts"
on public.posts for delete
to authenticated
using ( (select auth.uid()) = author_id );

commit;
