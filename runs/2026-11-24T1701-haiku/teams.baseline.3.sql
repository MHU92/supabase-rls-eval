begin;

-- Helper functions: SECURITY DEFINER so policy checks can read team_members
-- without recursing into its own RLS policies.
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

revoke all on function public.is_team_member(int) from public, anon;
revoke all on function public.is_team_admin(int) from public, anon;
grant execute on function public.is_team_member(int) to authenticated;
grant execute on function public.is_team_admin(int) to authenticated;

-- Enable RLS.
alter table public.teams enable row level security;
alter table public.team_members enable row level security;
alter table public.projects enable row level security;

-- Remove Supabase's default broad grants, then grant only what the rule needs.
-- RLS policies below then decide which rows each operation can touch.
revoke all on public.teams, public.team_members, public.projects from anon;
revoke all on public.teams, public.team_members, public.projects from authenticated;

grant select on public.teams, public.team_members, public.projects to authenticated;
grant insert, delete on public.team_members to authenticated;   -- no UPDATE: role changes are not part of the rule
grant insert, update, delete on public.projects to authenticated;

-- teams: members can read their own teams; no client-side writes.
create policy teams_select_member
  on public.teams for select to authenticated
  using (public.is_team_member(id));

-- team_members: members see their team's roster; only admins add/remove.
create policy team_members_select_member
  on public.team_members for select to authenticated
  using (public.is_team_member(team_id));

create policy team_members_insert_admin
  on public.team_members for insert to authenticated
  with check (public.is_team_admin(team_id));

create policy team_members_delete_admin
  on public.team_members for delete to authenticated
  using (public.is_team_admin(team_id));

-- projects: members read; only admins create, rename, delete.
create policy projects_select_member
  on public.projects for select to authenticated
  using (public.is_team_member(team_id));

create policy projects_insert_admin
  on public.projects for insert to authenticated
  with check (public.is_team_admin(team_id));

-- USING limits which rows can be updated; WITH CHECK stops a project
-- from being moved into another team.
create policy projects_update_admin
  on public.projects for update to authenticated
  using (public.is_team_admin(team_id))
  with check (public.is_team_admin(team_id));

create policy projects_delete_admin
  on public.projects for delete to authenticated
  using (public.is_team_admin(team_id));

commit;
