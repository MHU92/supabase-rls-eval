-- Blog posts: public read of published rows, author-owned writes.
alter table public.posts enable row level security;

-- Drop Supabase's default grants, then grant back only what each role needs.
revoke all on table public.posts from anon, authenticated;
grant select on table public.posts to anon;
grant select, insert, update, delete on table public.posts to authenticated;

-- Policies filter on author_id, so index it.
create index if not exists posts_author_id_idx
  on public.posts using btree (author_id);

-- Anyone, signed in or not, reads published posts.
drop policy if exists "Anyone can read published posts" on public.posts;
create policy "Anyone can read published posts"
on public.posts for select
to anon, authenticated
using ( published );

-- Signed-in authors also read their own drafts.
drop policy if exists "Authors can read their own posts" on public.posts;
create policy "Authors can read their own posts"
on public.posts for select
to authenticated
using ( (select auth.uid()) = author_id );

-- Signed-in users can create posts only as themselves.
drop policy if exists "Users can create their own posts" on public.posts;
create policy "Users can create their own posts"
on public.posts for insert
to authenticated
with check ( (select auth.uid()) = author_id );

-- Authors edit only their own posts, and cannot reassign author_id.
drop policy if exists "Authors can update their own posts" on public.posts;
create policy "Authors can update their own posts"
on public.posts for update
to authenticated
using ( (select auth.uid()) = author_id )
with check ( (select auth.uid()) = author_id );

-- Authors delete only their own posts.
drop policy if exists "Authors can delete their own posts" on public.posts;
create policy "Authors can delete their own posts"
on public.posts for delete
to authenticated
using ( (select auth.uid()) = author_id );
