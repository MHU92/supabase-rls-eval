-- Enable RLS on all tables
alter table public.teams enable row level security;
alter table public.team_members enable row level security;
alter table public.projects enable row level security;

-- Revoke default grants from client roles
revoke all on table public.teams from anon, authenticated;
revoke all on table public.team_members from anon, authenticated;
revoke all on table public.projects from anon, authenticated;

-- Grant back only what is needed
grant select on table public.teams to authenticated;
grant select, insert, delete on table public.team_members to authenticated;
grant select, insert, update, delete on table public.projects to authenticated;

-- Index for policy lookups (primary key only covers team_id as leading column)
create index if not exists team_members_user_id_idx
  on public.team_members using btree (user_id);

-- Private schema for security definer helpers (not exposed via the Data API)
create schema if not exists private;
revoke all on schema private from public;
grant usage on schema private to authenticated;

-- Teams the caller belongs to (any role)
create or replace function private.user_team_ids()
returns setof int
language sql
security definer
set search_path = ''
stable
as $$
  select team_id from public.team_members
  where user_id = (select auth.uid())
$$;

-- Teams the caller administers
create or replace function private.admin_team_ids()
returns setof int
language sql
security definer
set search_path = ''
stable
as $$
  select team_id from public.team_members
  where user_id = (select auth.uid()) and role = 'admin'
$$;

revoke execute on function private.user_team_ids() from public;
revoke execute on function private.admin_team_ids() from public;
grant execute on function private.user_team_ids() to authenticated;
grant execute on function private.admin_team_ids() to authenticated;

-- teams: members can read their own teams
create policy "Members can view their teams"
on public.teams for select
to authenticated
using ( id in (select private.user_team_ids()) );

-- team_members: members see who is in their team
create policy "Members can view their team's members"
on public.team_members for select
to authenticated
using ( team_id in (select private.user_team_ids()) );

-- team_members: only admins add members to their team
create policy "Admins can add team members"
on public.team_members for insert
to authenticated
with check ( team_id in (select private.admin_team_ids()) );

-- team_members: only admins remove members from their team
create policy "Admins can remove team members"
on public.team_members for delete
to authenticated
using ( team_id in (select private.admin_team_ids()) );

-- projects: members can read their team's projects
create policy "Members can view their team's projects"
on public.projects for select
to authenticated
using ( team_id in (select private.user_team_ids()) );

-- projects: only admins create projects
create policy "Admins can create projects"
on public.projects for insert
to authenticated
with check ( team_id in (select private.admin_team_ids()) );

-- projects: only admins rename projects (and cannot move them to another team)
create policy "Admins can update projects"
on public.projects for update
to authenticated
using ( team_id in (select private.admin_team_ids()) )
with check ( team_id in (select private.admin_team_ids()) );

-- projects: only admins delete projects
create policy "Admins can delete projects"
on public.projects for delete
to authenticated
using ( team_id in (select private.admin_team_ids()) );

-- Index to support project policy lookups
create index if not exists projects_team_id_idx
  on public.projects using btree (team_id);
