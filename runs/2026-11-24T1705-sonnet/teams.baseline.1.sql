-- Helper functions bypass RLS (security definer) so the team_members policies
-- do not recurse into themselves.
create schema if not exists private;
revoke all on schema private from public, anon;
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

revoke all on function private.is_team_member(int) from public, anon;
revoke all on function private.is_team_admin(int) from public, anon;
grant execute on function private.is_team_member(int) to authenticated;
grant execute on function private.is_team_admin(int) to authenticated;

-- Enable RLS
alter table public.teams enable row level security;
alter table public.team_members enable row level security;
alter table public.projects enable row level security;

-- Tighten the default grants
revoke all on public.teams from anon, authenticated;
revoke all on public.team_members from anon, authenticated;
revoke all on public.projects from anon, authenticated;

grant select on public.teams to authenticated;
grant select, insert, delete on public.team_members to authenticated;
grant select, insert, delete on public.projects to authenticated;
grant update (name) on public.projects to authenticated;  -- rename only; team_id cannot be moved

-- teams: members can see their own team (read-only)
create policy teams_select_member on public.teams
  for select to authenticated
  using (private.is_team_member(id));

-- team_members: members see their team's roster; admins add/remove members
create policy team_members_select on public.team_members
  for select to authenticated
  using (private.is_team_member(team_id));

create policy team_members_insert_admin on public.team_members
  for insert to authenticated
  with check (private.is_team_admin(team_id));

create policy team_members_delete_admin on public.team_members
  for delete to authenticated
  using (private.is_team_admin(team_id));

-- projects: members read; admins create/rename/delete
create policy projects_select on public.projects
  for select to authenticated
  using (private.is_team_member(team_id));

create policy projects_insert_admin on public.projects
  for insert to authenticated
  with check (private.is_team_admin(team_id));

create policy projects_update_admin on public.projects
  for update to authenticated
  using (private.is_team_admin(team_id))
  with check (private.is_team_admin(team_id));

create policy projects_delete_admin on public.projects
  for delete to authenticated
  using (private.is_team_admin(team_id));
