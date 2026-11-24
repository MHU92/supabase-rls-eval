-- Enable RLS on the table
alter table public.posts enable row level security;

-- Remove the default grants, then grant back only what each role needs
revoke all on table public.posts from anon, authenticated;

-- Signed-out visitors may only read (rows are limited to published posts by policy)
grant select on table public.posts to anon;

-- Signed-in users may read and manage posts (rows are limited by policies)
grant select, insert, update, delete on table public.posts to authenticated;

-- Index the column used by the policies
create index if not exists posts_author_id_idx
on public.posts using btree (author_id);

-- SELECT: anyone can read published posts
create policy "Anyone can read published posts"
on public.posts for select
to anon, authenticated
using ( published = true );

-- SELECT: authors can also read their own drafts
create policy "Authors can read their own posts"
on public.posts for select
to authenticated
using ( (select auth.uid()) = author_id );

-- INSERT: signed-in users can create posts only as themselves
create policy "Users can create their own posts"
on public.posts for insert
to authenticated
with check ( (select auth.uid()) = author_id );

-- UPDATE: authors can edit only their own posts and cannot reassign them
create policy "Authors can update their own posts"
on public.posts for update
to authenticated
using ( (select auth.uid()) = author_id )
with check ( (select auth.uid()) = author_id );

-- DELETE: authors can delete only their own posts
create policy "Authors can delete their own posts"
on public.posts for delete
to authenticated
using ( (select auth.uid()) = author_id );
