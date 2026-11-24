-- Migration: team-scoped access control with Row Level Security

create schema if not exists private;

-- Helpers run as their owner (postgres, which has bypassrls), so the policies
-- on team_members do not recurse into themselves.
create or replace function private.user_team_ids()
returns setof int
language sql
security definer
stable
set search_path = ''
as $$
  select tm.team_id
  from public.team_members tm
  where tm.user_id = (select auth.uid())
$$;

create or replace function private.user_admin_team_ids()
returns setof int
language sql
security definer
stable
set search_path = ''
as $$
  select tm.team_id
  from public.team_members tm
  where tm.user_id = (select auth.uid())
    and tm.role = 'admin'
$$;

revoke execute on function private.user_team_ids() from public;
revoke execute on function private.user_admin_team_ids() from public;
grant usage on schema private to authenticated;
grant execute on function private.user_team_ids() to authenticated;
grant execute on function private.user_admin_team_ids() to authenticated;

-- Indexes on the columns the policies filter on.
-- The primary key (team_id, user_id) does not index user_id on its own.
create index if not exists team_members_user_id_idx
  on public.team_members using btree (user_id);
create index if not exists projects_team_id_idx
  on public.projects using btree (team_id);

-- Enable RLS on every table in the exposed schema.
alter table public.teams enable row level security;
alter table public.team_members enable row level security;
alter table public.projects enable row level security;

-- Remove the default grants, then grant back only what the rule requires.
-- No client may write teams, and no client may change a member's role.
revoke all on table public.teams, public.team_members, public.projects
  from anon, authenticated;
grant select on table public.teams to authenticated;
grant select, insert, delete on table public.team_members to authenticated;
grant select, insert, update, delete on table public.projects to authenticated;

-- teams: members read their own team(s) only.
drop policy if exists "members read own teams" on public.teams;
create policy "members read own teams"
on public.teams for select
to authenticated
using ( id in (select private.user_team_ids()) );

-- team_members: members see who is in their team.
drop policy if exists "members read own team roster" on public.team_members;
create policy "members read own team roster"
on public.team_members for select
to authenticated
using ( team_id in (select private.user_team_ids()) );

-- team_members: only admins of a team add members to it.
drop policy if exists "admins add team members" on public.team_members;
create policy "admins add team members"
on public.team_members for insert
to authenticated
with check ( team_id in (select private.user_admin_team_ids()) );

-- team_members: only admins of a team remove members from it.
drop policy if exists "admins remove team members" on public.team_members;
create policy "admins remove team members"
on public.team_members for delete
to authenticated
using ( team_id in (select private.user_admin_team_ids()) );

-- projects: members read their own team's projects.
drop policy if exists "members read team projects" on public.projects;
create policy "members read team projects"
on public.projects for select
to authenticated
using ( team_id in (select private.user_team_ids()) );

-- projects: only admins create projects, and only in their own team.
drop policy if exists "admins create team projects" on public.projects;
create policy "admins create team projects"
on public.projects for insert
to authenticated
with check ( team_id in (select private.user_admin_team_ids()) );

-- projects: only admins rename projects. The with check also stops a
-- project from being moved into a team the admin does not administer.
drop policy if exists "admins update team projects" on public.projects;
create policy "admins update team projects"
on public.projects for update
to authenticated
using ( team_id in (select private.user_admin_team_ids()) )
with check ( team_id in (select private.user_admin_team_ids()) );

-- projects: only admins delete projects.
drop policy if exists "admins delete team projects" on public.projects;
create policy "admins delete team projects"
on public.projects for delete
to authenticated
using ( team_id in (select private.user_admin_team_ids()) );
