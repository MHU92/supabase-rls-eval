-- Enable RLS on the table
alter table public.posts enable row level security;

-- Remove the default grants, then grant back only what each role needs
revoke all on table public.posts from anon, authenticated;
grant select on table public.posts to anon;
grant select, insert, update, delete on table public.posts to authenticated;

-- Index the column used by the policies
create index if not exists posts_author_id_idx
on public.posts using btree (author_id);

-- SELECT: anyone can read published posts
create policy "Anyone can read published posts"
on public.posts for select
to anon
using ( published = true );

-- SELECT: signed-in users read published posts and their own drafts
create policy "Authenticated users can read published posts and own drafts"
on public.posts for select
to authenticated
using (
  published = true
  or (select auth.uid()) = author_id
);

-- INSERT: signed-in users can create posts only as themselves
create policy "Authenticated users can create their own posts"
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
