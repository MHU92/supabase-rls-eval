alter table public.posts enable row level security;

revoke all on table public.posts from anon, authenticated;
grant select on table public.posts to anon, authenticated;
grant insert, update, delete on table public.posts to authenticated;

create index if not exists posts_author_id_idx
on public.posts using btree (author_id);

create policy "Anyone can read published posts, authors can read their own drafts"
on public.posts for select
to anon, authenticated
using (
  published
  or ((select auth.uid()) is not null and (select auth.uid()) = author_id)
);

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
