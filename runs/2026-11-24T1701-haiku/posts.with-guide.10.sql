-- Migration: blog posts RLS
-- Access rule:
--   * anon + authenticated: read published posts
--   * authenticated: read own drafts
--   * authenticated: insert only as self, update/delete only own posts
--   * anon: no writes

alter table public.posts enable row level security;

-- Remove the default grants that Supabase gives anon and authenticated.
revoke all on table public.posts from anon, authenticated;

-- anon reads published posts only. No write grant.
grant select on table public.posts to anon;

-- authenticated reads, creates, edits and deletes posts. RLS narrows which rows.
grant select, insert, update, delete on table public.posts to authenticated;

-- Index the column the policies filter on.
create index if not exists posts_author_id_idx
  on public.posts using btree (author_id);

create policy "Anyone can read published posts"
on public.posts for select
to anon, authenticated
using ( published = true );

create policy "Authors can read their own drafts"
on public.posts for select
to authenticated
using ( (select auth.uid()) = author_id );

create policy "Signed-in users can create posts as themselves"
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
