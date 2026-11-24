-- Helper functions: SECURITY DEFINER so policy checks can read team_members
-- without re-triggering RLS on that table (avoids policy recursion).
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

-- Remove Supabase's default broad grants on the affected tables.
revoke all on public.teams, public.team_members, public.projects from anon, authenticated;

-- Grant only what the access rule needs; RLS policies below narrow it further.
grant select on public.teams, public.team_members, public.projects to authenticated;
grant insert, delete on public.team_members to authenticated;
grant insert, update, delete on public.projects to authenticated;

-- Enable RLS.
alter table public.teams enable row level security;
alter table public.team_members enable row level security;
alter table public.projects enable row level security;

-- teams: members can see their own team only. No write access.
create policy teams_select_member
  on public.teams for select
  to authenticated
  using (public.is_team_member(id));

-- team_members: members see their team's roster.
create policy team_members_select_member
  on public.team_members for select
  to authenticated
  using (public.is_team_member(team_id));

-- Only admins add members to their team.
create policy team_members_insert_admin
  on public.team_members for insert
  to authenticated
  with check (public.is_team_admin(team_id));

-- Only admins remove members from their team. No UPDATE policy/grant (role changes not permitted).
create policy team_members_delete_admin
  on public.team_members for delete
  to authenticated
  using (public.is_team_admin(team_id));

-- projects: members read their team's projects.
create policy projects_select_member
  on public.projects for select
  to authenticated
  using (public.is_team_member(team_id));

-- Only admins create projects in their team.
create policy projects_insert_admin
  on public.projects for insert
  to authenticated
  with check (public.is_team_admin(team_id));

-- Only admins rename projects; WITH CHECK prevents moving a project to another team.
create policy projects_update_admin
  on public.projects for update
  to authenticated
  using (public.is_team_admin(team_id))
  with check (public.is_team_admin(team_id));

-- Only admins delete projects in their team.
create policy projects_delete_admin
  on public.projects for delete
  to authenticated
  using (public.is_team_admin(team_id));
