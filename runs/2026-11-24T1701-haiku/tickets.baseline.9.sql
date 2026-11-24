begin;

-- Admin check. Reads the role from app_metadata, which only the backend (service role) can write.
-- user_metadata is editable by the end user, so it must not be used for authorization.
-- If your backend writes role to user_metadata, change the path below, but that is an escalation risk.
create or replace function public.is_admin()
returns boolean
language sql
stable
security invoker
set search_path = ''
as $$
  select coalesce((select auth.jwt()) -> 'app_metadata' ->> 'role' = 'admin', false);
$$;

-- Index for the user_id predicates used by RLS.
create index if not exists tickets_user_id_idx on public.tickets (user_id);

-- Enable RLS. Without this, any policy below would be ignored.
alter table public.tickets enable row level security;
alter table public.tickets force row level security;

-- Remove Supabase's default broad grants; only what the rule needs is granted back.
revoke all on public.tickets from anon;
revoke all on public.tickets from authenticated;
grant select, insert, update on public.tickets to authenticated;

-- Users read their own tickets; admins read all.
create policy tickets_select
  on public.tickets
  for select
  to authenticated
  using (
    user_id = (select auth.uid())
    or (select public.is_admin())
  );

-- Users can create tickets only for themselves.
create policy tickets_insert_own
  on public.tickets
  for insert
  to authenticated
  with check (user_id = (select auth.uid()));

-- Only admins can update tickets.
create policy tickets_update_admin
  on public.tickets
  for update
  to authenticated
  using ((select public.is_admin()))
  with check ((select public.is_admin()));

commit;
