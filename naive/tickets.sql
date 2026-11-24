-- Typical mistake: the admin flag is read from user_metadata, which every user can edit for themselves.
alter table public.tickets enable row level security;
create policy "tickets: own or admin" on public.tickets for select
  using (auth.uid() = user_id or (auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');
create policy "tickets: create own" on public.tickets for insert with check (auth.uid() = user_id);
create policy "tickets: admins update" on public.tickets for update using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');
