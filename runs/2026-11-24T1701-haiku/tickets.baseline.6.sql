-- Row Level Security for public.tickets
-- Admin role is read from app_metadata, which only the service role can write.
-- user_metadata is writable by the end user via supabase.auth.updateUser(), so it must not grant admin rights.

alter table public.tickets enable row level security;
alter table public.tickets force row level security;

-- Anonymous visitors get nothing from this table.
revoke all on public.tickets from anon;

-- Index supporting the user_id = auth.uid() checks.
create index if not exists tickets_user_id_idx on public.tickets (user_id);

drop policy if exists tickets_select_own_or_admin on public.tickets;
create policy tickets_select_own_or_admin
  on public.tickets
  for select
  to authenticated
  using (
    user_id = (select auth.uid())
    or (select auth.jwt()) -> 'app_metadata' ->> 'role' = 'admin'
  );

drop policy if exists tickets_insert_own on public.tickets;
create policy tickets_insert_own
  on public.tickets
  for insert
  to authenticated
  with check (
    user_id = (select auth.uid())
  );

drop policy if exists tickets_update_admin on public.tickets;
create policy tickets_update_admin
  on public.tickets
  for update
  to authenticated
  using (
    (select auth.jwt()) -> 'app_metadata' ->> 'role' = 'admin'
  )
  with check (
    (select auth.jwt()) -> 'app_metadata' ->> 'role' = 'admin'
  );
