-- The admin flag comes from app_metadata, which only the backend can set; user_metadata is editable by the user.
alter table public.tickets enable row level security;
revoke all on public.tickets from anon;
create policy "tickets: own or admin" on public.tickets for select to authenticated
  using ((select auth.uid()) = user_id or (select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');
create policy "tickets: create own" on public.tickets for insert to authenticated with check ((select auth.uid()) = user_id);
create policy "tickets: admins update" on public.tickets for update to authenticated
  using ((select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin') with check ((select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');
