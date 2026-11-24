-- Row Level Security for public.tickets
-- Users read and create their own tickets. Admins read and update all tickets.

alter table public.tickets enable row level security;

-- Anonymous callers get no access at all.
revoke all on public.tickets from anon;

-- Admin check. Reads app_metadata, which only the server can write. Do not use
-- user_metadata here: users can change their own user_metadata via the client SDK,
-- which would let anyone make themselves admin.
create or replace function public.is_ticket_admin()
returns boolean
language sql
stable
security invoker
set search_path = ''
as $$
  select coalesce((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin', false);
$$;

drop policy if exists tickets_select_own_or_admin on public.tickets;
create policy tickets_select_own_or_admin on public.tickets
  for select
  to authenticated
  using (
    user_id = (select auth.uid())
    or (select public.is_ticket_admin())
  );

drop policy if exists tickets_insert_own on public.tickets;
create policy tickets_insert_own on public.tickets
  for insert
  to authenticated
  with check (user_id = (select auth.uid()));

drop policy if exists tickets_update_admin on public.tickets;
create policy tickets_update_admin on public.tickets
  for update
  to authenticated
  using ((select public.is_ticket_admin()))
  with check ((select public.is_ticket_admin()));
