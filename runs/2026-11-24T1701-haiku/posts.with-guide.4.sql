-- Migration: RLS for public.posts
-- Access rule:
--   * anon + authenticated may read published posts
--   * authors may also read their own drafts
--   * authenticated users may insert only as themselves
--   * authenticated users may update/delete only their own posts
--   * anon cannot write

-- 1. Enable RLS and revoke default grants from client roles
alter table public.posts enable row level security;
revoke all on table public.posts from anon, authenticated;

-- 2. Grant back only what each role needs
grant select on table public.posts to anon, authenticated;
grant insert, update, delete on table public.posts to authenticated;

-- 3. Index the policy filter column
create index if not exists posts_author_id_idx
  on public.posts using btree (author_id);

-- 4. Policies (one per operation)
create policy "Anyone can read published posts"
on public.posts for select
to anon, authenticated
using ( published = true );

create policy "Authors can read their own posts"
on public.posts for select
to authenticated
using ( (select auth.uid()) = author_id );

create policy "Authenticated users can create posts as themselves"
on public.posts for insert
to authenticated
with check ( (select auth.uid()) = author_id );

create policy "Authors can update their own posts"
on public.posts for update
to authenticated
using ( (select auth.uid()) = author_id )
with check ( (select auth.uid()) = author_id );

create policy "Authors can delete their own posts"
on public.posts for delete
to authenticated
using ( (select auth.uid()) = author_id );
