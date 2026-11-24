-- Migration: team-based RLS for teams, team_members, projects
-- Access rule:
--   * Members (role 'admin' or 'member') can read their team's projects and see team membership.
--   * Only team admins can insert/update/delete projects and insert/delete team members.
--   * No cross-team visibility or changes.

-- 1. Enable RLS on every table in the exposed schema
alter table public.teams enable row level security;
alter table public.team_members enable row level security;
alter table public.projects enable row level security;

-- 2. Revoke default grants from client roles
revoke all on table public.teams from anon, authenticated;
revoke all on table public.team_members from anon, authenticated;
revoke all on table public.projects from anon, authenticated;

-- 3. Grant back only what is needed
grant select on table public.teams to authenticated;
grant select on table public.team_members to authenticated;
grant select, insert, update, delete on table public.projects to authenticated;
grant insert, delete on table public.team_members to authenticated;

-- 4. Indexes for policy filter columns
-- team_members PK (team_id, user_id) covers team_id; user_id needs its own index.
create index if not exists team_members_user_id_idx
  on public.team_members using btree (user_id);
create index if not exists projects_team_id_idx
  on public.projects using btree (team_id);

-- 5. Helper functions (security definer, search_path pinned, bypass RLS to avoid recursion)
create schema if not exists private;
revoke all on schema private from public;
grant usage on schema private to authenticated;

create or replace function private.is_team_member(p_team_id int)
returns boolean
language sql
security definer
stable
set search_path = ''
as $$
  select exists (
    select 1 from public.team_members tm
    where tm.team_id = p_team_id
      and tm.user_id = (select auth.uid())
  );
$$;

create or replace function private.is_team_admin(p_team_id int)
returns boolean
language sql
security definer
stable
set search_path = ''
as $$
  select exists (
    select 1 from public.team_members tm
    where tm.team_id = p_team_id
      and tm.user_id = (select auth.uid())
      and tm.role = 'admin'
  );
$$;

revoke execute on function private.is_team_member(int) from public;
revoke execute on function private.is_team_admin(int) from public;
grant execute on function private.is_team_member(int) to authenticated;
grant execute on function private.is_team_admin(int) to authenticated;

-- 6. teams policies: members can read their own team
create policy "teams: members read own team"
on public.teams for select
to authenticated
using ( (select private.is_team_member(id)) );

-- 7. team_members policies
create policy "team_members: members see their team's roster"
on public.team_members for select
to authenticated
using ( (select private.is_team_member(team_id)) );

create policy "team_members: admins add members"
on public.team_members for insert
to authenticated
with check ( (select private.is_team_admin(team_id)) );

create policy "team_members: admins remove members"
on public.team_members for delete
to authenticated
using ( (select private.is_team_admin(team_id)) );

-- 8. projects policies
create policy "projects: members read their team's projects"
on public.projects for select
to authenticated
using ( (select private.is_team_member(team_id)) );

create policy "projects: admins create projects"
on public.projects for insert
to authenticated
with check ( (select private.is_team_admin(team_id)) );

create policy "projects: admins rename projects"
on public.projects for update
to authenticated
using ( (select private.is_team_admin(team_id)) )
with check ( (select private.is_team_admin(team_id)) );

create policy "projects: admins delete projects"
on public.projects for delete
to authenticated
using ( (select private.is_team_admin(team_id)) );
