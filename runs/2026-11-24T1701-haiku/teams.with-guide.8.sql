-- Migration: team-scoped access control with Row Level Security.
-- Rule: members read their team's projects and roster; only team admins
-- create, rename, or delete projects and add or remove members.
-- Helpers are security definer so policies on team_members do not recurse.

begin;

-- 1. Helper functions in a private schema (not exposed through the Data API).
create schema if not exists private;
grant usage on schema private to authenticated;

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

revoke execute on function private.is_team_member(int) from public;
revoke execute on function private.is_team_admin(int) from public;
grant execute on function private.is_team_member(int) to authenticated;
grant execute on function private.is_team_admin(int) to authenticated;

-- 2. Indexes for the columns the policies filter on.
-- The primary key (team_id, user_id) does not index user_id on its own.
create index if not exists team_members_user_id_idx
  on public.team_members (user_id);
create index if not exists projects_team_id_idx
  on public.projects (team_id);

-- 3. Enable RLS and reset grants. anon gets nothing; authenticated gets
--    only the operations the rule allows.
alter table public.teams enable row level security;
alter table public.team_members enable row level security;
alter table public.projects enable row level security;

revoke all on table public.teams from anon, authenticated;
revoke all on table public.team_members from anon, authenticated;
revoke all on table public.projects from anon, authenticated;

-- Teams: members read their own team. Team create/rename/delete is not
-- part of the rule, so no write grant.
grant select on table public.teams to authenticated;

-- Roster: members read it; admins add and remove. No update path,
-- since the rule covers adding and removing only.
grant select, insert, delete on table public.team_members to authenticated;

-- Projects: members read; admins create, rename, and delete.
grant select, insert, update, delete on table public.projects to authenticated;

-- 4. Policies, one per operation.

-- teams
create policy "Members can view their team"
on public.teams for select
to authenticated
using ( private.is_team_member(id) );

-- team_members
create policy "Members can view their team's roster"
on public.team_members for select
to authenticated
using ( private.is_team_member(team_id) );

create policy "Admins can add members to their team"
on public.team_members for insert
to authenticated
with check ( private.is_team_admin(team_id) );

create policy "Admins can remove members from their team"
on public.team_members for delete
to authenticated
using ( private.is_team_admin(team_id) );

-- projects
create policy "Members can view their team's projects"
on public.projects for select
to authenticated
using ( private.is_team_member(team_id) );

create policy "Admins can create projects for their team"
on public.projects for insert
to authenticated
with check ( private.is_team_admin(team_id) );

-- The using clause decides which rows an admin can change. The with check
-- clause stops an admin from moving a project into a team they do not admin.
create policy "Admins can update their team's projects"
on public.projects for update
to authenticated
using ( private.is_team_admin(team_id) )
with check ( private.is_team_admin(team_id) );

create policy "Admins can delete their team's projects"
on public.projects for delete
to authenticated
using ( private.is_team_admin(team_id) );

commit;
