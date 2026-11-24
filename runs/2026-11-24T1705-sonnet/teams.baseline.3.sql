-- Helper functions live in a non-exposed schema and run as SECURITY DEFINER,
-- so policies on team_members can check membership without recursing into RLS.
create schema if not exists private;
revoke all on schema private from public;
grant usage on schema private to authenticated;

create or replace function private.is_team_member(_team_id int)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.team_members tm
    where tm.team_id = _team_id
      and tm.user_id = (select auth.uid())
  );
$$;

create or replace function private.is_team_admin(_team_id int)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.team_members tm
    where tm.team_id = _team_id
      and tm.user_id = (select auth.uid())
      and tm.role = 'admin'
  );
$$;

revoke all on function private.is_team_member(int) from public;
revoke all on function private.is_team_admin(int) from public;
grant execute on function private.is_team_member(int) to authenticated;
grant execute on function private.is_team_admin(int) to authenticated;

-- Enable RLS
alter table public.teams enable row level security;
alter table public.team_members enable row level security;
alter table public.projects enable row level security;

-- Tighten default grants: no anonymous access, only the privileges needed
revoke all on public.teams from anon, authenticated;
revoke all on public.team_members from anon, authenticated;
revoke all on public.projects from anon, authenticated;

grant select on public.teams to authenticated;
grant select, insert, delete on public.team_members to authenticated;
grant select, insert, update, delete on public.projects to authenticated;

-- teams: members can see their own team
create policy "members can read own team"
  on public.teams for select
  to authenticated
  using (private.is_team_member(id));

-- team_members: members see their team's roster; admins add/remove members
create policy "members can read own team roster"
  on public.team_members for select
  to authenticated
  using (private.is_team_member(team_id));

create policy "admins can add members"
  on public.team_members for insert
  to authenticated
  with check (private.is_team_admin(team_id));

create policy "admins can remove members"
  on public.team_members for delete
  to authenticated
  using (private.is_team_admin(team_id));

-- projects: members read; admins create, update, delete
create policy "members can read own team projects"
  on public.projects for select
  to authenticated
  using (private.is_team_member(team_id));

create policy "admins can create projects"
  on public.projects for insert
  to authenticated
  with check (private.is_team_admin(team_id));

create policy "admins can update projects"
  on public.projects for update
  to authenticated
  using (private.is_team_admin(team_id))
  with check (private.is_team_admin(team_id));

create policy "admins can delete projects"
  on public.projects for delete
  to authenticated
  using (private.is_team_admin(team_id));
