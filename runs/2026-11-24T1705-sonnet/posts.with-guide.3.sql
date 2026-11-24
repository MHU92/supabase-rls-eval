-- Enable RLS
alter table public.posts enable row level security;

-- Reset grants: default grants give anon/authenticated everything
revoke all on table public.posts from anon, authenticated;

-- anon: read only; authenticated: read and write
grant select on table public.posts to anon;
grant select, insert, update, delete on table public.posts to authenticated;

-- SELECT: anyone reads published posts
create policy "Anyone can read published posts"
on public.posts for select
to anon, authenticated
using ( published );

-- SELECT: authors also read their own drafts
create policy "Authors can read their own posts"
on public.posts for select
to authenticated
using ( (select auth.uid()) = author_id );

-- INSERT: signed-in users can only create posts as themselves
create policy "Users can create their own posts"
on public.posts for insert
to authenticated
with check ( (select auth.uid()) = author_id );

-- UPDATE: only own posts, and they must remain own posts
create policy "Users can update their own posts"
on public.posts for update
to authenticated
using ( (select auth.uid()) = author_id )
with check ( (select auth.uid()) = author_id );

-- DELETE: only own posts
create policy "Users can delete their own posts"
on public.posts for delete
to authenticated
using ( (select auth.uid()) = author_id );

-- Index the column used by the policies
create index posts_author_id_idx on public.posts using btree (author_id);
