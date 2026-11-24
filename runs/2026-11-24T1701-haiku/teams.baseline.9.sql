-- Helper functions. SECURITY DEFINER lets them read team_members without
-- re-triggering that table's RLS policies (avoids recursion).
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
      and tm.user_id = auth.uid()
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
      and tm.user_id = auth.uid()
      and tm.role = 'admin'
  );
$$;

revoke execute on function public.is_team_member(int) from public, anon;
revoke execute on function public.is_team_admin(int) from public, anon;
grant execute on function public.is_team_member(int) to authenticated;
grant execute on function public.is_team_admin(int) to authenticated;

-- Remove Supabase's default broad grants; re-grant only what the rule needs.
-- RLS policies below then restrict the actual rows.
revoke all on public.teams, public.team_members, public.projects from anon, authenticated;

grant select on public.teams, public.team_members, public.projects to authenticated;
grant insert, update, delete on public.projects to authenticated;
grant insert, delete on public.team_members to authenticated;

-- Enable RLS.
alter table public.teams enable row level security;
alter table public.team_members enable row level security;
alter table public.projects enable row level security;

-- teams: members can see their own team; no one can create/change/delete teams via the API.
create policy teams_select_member on public.teams
  for select to authenticated
  using (public.is_team_member(id));

-- team_members: members see everyone in their team; only admins add/remove members.
-- No UPDATE policy, so role changes are not allowed through the API.
create policy team_members_select_same_team on public.team_members
  for select to authenticated
  using (public.is_team_member(team_id));

create policy team_members_insert_admin on public.team_members
  for insert to authenticated
  with check (public.is_team_admin(team_id));

create policy team_members_delete_admin on public.team_members
  for delete to authenticated
  using (public.is_team_admin(team_id));

-- projects: members read their team's projects; only admins create, rename, or delete them.
create policy projects_select_member on public.projects
  for select to authenticated
  using (public.is_team_member(team_id));

create policy projects_insert_admin on public.projects
  for insert to authenticated
  with check (public.is_team_admin(team_id));

create policy projects_update_admin on public.projects
  for update to authenticated
  using (public.is_team_admin(team_id))
  with check (public.is_team_admin(team_id));

create policy projects_delete_admin on public.projects
  for delete to authenticated
  using (public.is_team_admin(team_id));
