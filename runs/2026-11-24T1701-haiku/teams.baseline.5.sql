-- Migration: row level security for teams, team_members and projects

-- Helper functions. SECURITY DEFINER lets them read team_members without
-- re-triggering its RLS policies (avoids policy recursion).
create or replace function public.is_team_member(p_team_id int)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.team_members tm
    where tm.team_id = p_team_id
      and tm.user_id = (select auth.uid())
  );
$$;

create or replace function public.is_team_admin(p_team_id int)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.team_members tm
    where tm.team_id = p_team_id
      and tm.user_id = (select auth.uid())
      and tm.role = 'admin'
  );
$$;

revoke execute on function public.is_team_member(int) from public, anon;
revoke execute on function public.is_team_admin(int) from public, anon;
grant execute on function public.is_team_member(int) to authenticated;
grant execute on function public.is_team_admin(int) to authenticated;

-- Remove Supabase's default grants, then grant only what the rules need.
-- RLS policies below further restrict each operation.
revoke all on public.teams, public.team_members, public.projects from anon, authenticated;

grant select on public.teams, public.team_members, public.projects to authenticated;
grant insert, update, delete on public.projects to authenticated;
grant insert, delete on public.team_members to authenticated;
-- teams: no write grants. team_members: no update grant (membership is add/remove only).

-- Enable RLS (deny by default when no policy matches)
alter table public.teams enable row level security;
alter table public.team_members enable row level security;
alter table public.projects enable row level security;

-- teams: members can read their own teams
create policy teams_select_member
  on public.teams for select to authenticated
  using (public.is_team_member(id));

-- team_members: members can see who is in their team
create policy team_members_select_member
  on public.team_members for select to authenticated
  using (public.is_team_member(team_id));

-- team_members: only team admins can add or remove members of their team
create policy team_members_insert_admin
  on public.team_members for insert to authenticated
  with check (public.is_team_admin(team_id));

create policy team_members_delete_admin
  on public.team_members for delete to authenticated
  using (public.is_team_admin(team_id));

-- projects: members can read their team's projects
create policy projects_select_member
  on public.projects for select to authenticated
  using (public.is_team_member(team_id));

-- projects: only team admins can create projects in their team
create policy projects_insert_admin
  on public.projects for insert to authenticated
  with check (public.is_team_admin(team_id));

-- projects: only team admins can rename projects; they cannot move a project
-- into a team they do not administer (WITH CHECK)
create policy projects_update_admin
  on public.projects for update to authenticated
  using (public.is_team_admin(team_id))
  with check (public.is_team_admin(team_id));

-- projects: only team admins can delete their team's projects
create policy projects_delete_admin
  on public.projects for delete to authenticated
  using (public.is_team_admin(team_id));
