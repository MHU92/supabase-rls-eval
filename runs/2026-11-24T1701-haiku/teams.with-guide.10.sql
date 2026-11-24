-- Team-scoped access control for teams, team_members and projects.
-- Assumes the three tables above already exist with data.

create schema if not exists private;

-- Membership helpers. security definer lets them read team_members without
-- re-entering its own RLS policies, which would recurse.
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
  )
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
  )
$$;

revoke execute on function private.is_team_member(int) from public, anon;
revoke execute on function private.is_team_admin(int) from public, anon;
grant usage on schema private to authenticated;
grant execute on function private.is_team_member(int) to authenticated;
grant execute on function private.is_team_admin(int) to authenticated;

-- Indexes for the columns the policies filter on.
-- team_members (team_id, user_id) is covered by the primary key.
create index if not exists team_members_user_id_idx on public.team_members (user_id);
create index if not exists projects_team_id_idx on public.projects (team_id);

-- Enable RLS.
alter table public.teams enable row level security;
alter table public.team_members enable row level security;
alter table public.projects enable row level security;

-- Remove default grants from the client roles.
revoke all on table public.teams from anon, authenticated;
revoke all on table public.team_members from anon, authenticated;
revoke all on table public.projects from anon, authenticated;

-- Grant back only what the rule allows.
-- teams: read only. No client writes.
grant select on table public.teams to authenticated;
-- team_members: read and admin add/remove. No update (role changes are not in the rule).
grant select, insert, delete on table public.team_members to authenticated;
-- projects: read, admin create/delete, admin rename. Only name is updatable, so team_id cannot be moved.
grant select, insert, delete on table public.projects to authenticated;
grant update (name) on table public.projects to authenticated;

-- teams
create policy "Members can view their team"
on public.teams for select
to authenticated
using ( private.is_team_member(id) );

-- team_members
create policy "Members can view their team's membership"
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

create policy "Admins can create projects in their team"
on public.projects for insert
to authenticated
with check ( private.is_team_admin(team_id) );

create policy "Admins can rename their team's projects"
on public.projects for update
to authenticated
using ( private.is_team_admin(team_id) )
with check ( private.is_team_admin(team_id) );

create policy "Admins can delete their team's projects"
on public.projects for delete
to authenticated
using ( private.is_team_admin(team_id) );
