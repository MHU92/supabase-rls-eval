-- Access rule for public.tickets:
--  * Users can read and create their own tickets.
--  * Admins can read and update every ticket.
-- The admin role is read from app_metadata, not user_metadata. Only the
-- backend (service role) can write app_metadata. user_metadata can be changed
-- by the signed-in user, so checking it would let anyone grant themselves admin.

-- Helper: true when the caller's JWT carries app_metadata.role = 'admin'.
create or replace function public.is_admin()
returns boolean
language sql
stable
set search_path = ''
as $$
  select coalesce((select auth.jwt()) -> 'app_metadata' ->> 'role' = 'admin', false);
$$;

-- Index for the user_id policy checks and for user ticket listings.
create index if not exists tickets_user_id_idx on public.tickets (user_id);

-- Turn on RLS. Without policies, everything is denied for non-owners.
alter table public.tickets enable row level security;

-- Remove the default grants. RLS still applies, but explicit grants keep the
-- surface small. There is intentionally no DELETE grant or policy.
revoke all on public.tickets from anon;
revoke all on public.tickets from authenticated;
grant select, insert, update on public.tickets to authenticated;

drop policy if exists tickets_select_own_or_admin on public.tickets;
create policy tickets_select_own_or_admin
  on public.tickets
  for select
  to authenticated
  using (
    user_id = (select auth.uid())
    or (select public.is_admin())
  );

drop policy if exists tickets_insert_own on public.tickets;
create policy tickets_insert_own
  on public.tickets
  for insert
  to authenticated
  with check (user_id = (select auth.uid()));

drop policy if exists tickets_update_admin on public.tickets;
create policy tickets_update_admin
  on public.tickets
  for update
  to authenticated
  using ((select public.is_admin()))
  with check ((select public.is_admin()));
