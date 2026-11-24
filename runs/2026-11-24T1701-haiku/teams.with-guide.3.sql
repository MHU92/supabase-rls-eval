```sql
-- Row Level Security for teams, team_members, and projects.

-- Helper functions: run as the owner (postgres, bypassrls) so policies on
-- team_members do not recurse into themselves.
create schema if not exists private;
grant usage on schema private to authenticated;

create or replace function private.my_team_ids()
returns setof int
language sql
stable
security definer
set search_path = ''
as $$
  select tm.team_id
  from public.team_members tm
  where tm.user_id = (select auth.uid())
$$;

create or replace function private.my_admin_team_ids()
returns setof int
language sql
stable
security definer
set search_path = ''
as $$
  select tm.team_id
  from public.team_members tm
  where tm.user_id = (select auth.uid())
    and tm.role = 'admin'
$$;

revoke execute on function private.my_team_ids() from public;
revoke execute on function private.my_admin_team_ids() from public;
grant execute on function private.my_team_ids() to authenticated;
grant execute on function private.my_admin_team_ids() to authenticated;

-- Indexes for the columns the policies filter on.
-- The primary key (team_id, user_id) does not index user_id on its own.
create index if not exists team_members_user_id_idx
  on public.team_members using btree (user_id);
create index if not exists projects_team_id_idx
  on public.projects using btree (team_id);

-- Enable RLS on every table.
alter table public.teams enable row level security;
alter table public.team_members enable row level security;
alter table public.projects enable row level security;

-- Remove the default grants, then grant back only what the rule needs.
revoke all on table public.teams, public.team_members, public.projects
  from anon, authenticated;

grant select on table public.teams to authenticated;
grant select, insert, delete on table public.team_members to authenticated;
grant select, insert, update, delete on table public.projects to authenticated;

-- teams: members read their own teams.
create policy "members read their teams"
on public.teams for select
to authenticated
using ( id in (select private.my_team_ids()) );

-- team_members: members see the roster of their teams.
create policy "members read their team roster"
on public.team_members for select
to authenticated
using ( team_id in (select private.my_team_ids()) );

-- team_members: only team admins add members to their team.
create policy "admins add team members"
on public.team_members for insert
to authenticated
with check ( team_id in (select private.my_admin_team_ids()) );

-- team_members: only team admins remove members from their team.
create policy "admins remove team members"
on public.team_members for delete
to authenticated
using ( team_id in (select private.my_admin_team_ids()) );

-- projects: members read their team's projects.
create policy "members read team projects"
on public.projects for select
to authenticated
using ( team_id in (select private.my_team_ids()) );

-- projects: only team admins create projects in their team.
create policy "admins create team projects"
on public.projects for insert
to authenticated
with check ( team_id in (select private.my_admin_team_ids()) );

-- projects: only team admins rename projects. The with check stops a project
-- from being moved into a team the admin does not administer.
create policy "admins rename team projects"
on public.projects for update
to authenticated
using ( team_id in (select private.my_admin_team_ids()) )
with check ( team_id in (select private.my_admin_team_ids()) );

-- projects: only team admins delete projects.
create policy "admins delete team projects"
on public.projects for delete
to authenticated
using ( team_id in (select private.my_admin_team_ids()) );