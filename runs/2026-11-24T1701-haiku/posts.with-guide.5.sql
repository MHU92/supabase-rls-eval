alter table public.posts enable row level security;

revoke all on table public.posts from anon, authenticated;
grant select on table public.posts to anon, authenticated;
grant insert, update, delete on table public.posts to authenticated;

create index if not exists posts_author_id_idx
  on public.posts using btree (author_id);

-- Anyone sees published posts; signed-in authors also see their own drafts.
create policy "Read published posts or own drafts"
on public.posts for select
to anon, authenticated
using (
  published
  or (
    (select auth.uid()) is not null
    and (select auth.uid()) = author_id
  )
);

-- Signed-in users can create posts only as themselves.
create policy "Authors insert their own posts"
on public.posts for insert
to authenticated
with check ( (select auth.uid()) = author_id );

-- Authors edit only their own posts, and cannot reassign author_id to someone else.
create policy "Authors update their own posts"
on public.posts for update
to authenticated
using ( (select auth.uid()) = author_id )
with check ( (select auth.uid()) = author_id );

-- Authors delete only their own posts.
create policy "Authors delete their own posts"
on public.posts for delete
to authenticated
using ( (select auth.uid()) = author_id );
