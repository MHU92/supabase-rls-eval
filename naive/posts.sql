-- Typical mistake: one policy for every command and every role. Reading is right, writing is open.
alter table public.posts enable row level security;
create policy "posts: access" on public.posts using (published or auth.uid() = author_id);
