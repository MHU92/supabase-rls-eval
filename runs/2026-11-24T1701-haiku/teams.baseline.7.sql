-- Helper schema, not exposed through the Data API
create schema if not exists private;
revoke all on schema private from public;
grant usage on schema private to authenticated;

-- Membership helpers. SECURITY DEFINER lets them read team_members without
-- re-applying its RLS policies, which avoids policy recursion.
create or replace function private.is_team_member(p_team_id int)
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

create or replace function private.is_team_admin(p_team_id int)
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

revoke all on function private.is_team_member(int) from public, anon;
revoke all on function private.is_team_admin(int) from public, anon;
grant execute on function private.is_team_member(int) to authenticated;
grant execute on function private.is_team_admin(int) to authenticated;

-- Remove Supabase's default table grants for anon and authenticated.
-- Access is granted explicitly below, and RLS policies limit the rows.
revoke all on public.teams, public.team_members, public.projects from anon, authenticated;

grant select on public.teams, public.team_members, public.projects to authenticated;
grant insert, delete on public.team_members to authenticated;
grant insert, delete on public.projects to authenticated;
-- Only the name can be updated, so a project cannot be moved to another team.
grant update (name) on public.projects to authenticated;

alter table public.teams enable row level security;
alter table public.team_members enable row level security;
alter table public.projects enable row level security;

-- teams: members can read their own teams. No write policies, so writes are denied.
create policy teams_select_member on public.teams
  for select to authenticated
  using (private.is_team_member(id));

-- team_members: members see their team's roster; only admins add or remove members.
create policy team_members_select_member on public.team_members
  for select to authenticated
  using (private.is_team_member(team_id));

create policy team_members_insert_admin on public.team_members
  for insert to authenticated
  with check (private.is_team_admin(team_id));

create policy team_members_delete_admin on public.team_members
  for delete to authenticated
  using (private.is_team_admin(team_id));

-- projects: members read; only admins create, rename, or delete.
create policy projects_select_member on public.projects
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
