-- Team-scoped access for teams, team_members and projects.

-- 1. Helper functions. They run as the owner (postgres, which has bypassrls),
--    so policies on team_members do not recurse into themselves.
create schema if not exists private;

create or replace function private.is_team_member(p_team_id int)
returns boolean
language sql
security definer
stable
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
security definer
stable
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
grant usage on schema private to authenticated;
grant execute on function private.is_team_member(int) to authenticated;
grant execute on function private.is_team_admin(int) to authenticated;

-- 2. Indexes for the columns the policies filter on.
--    The primary key (team_id, user_id) does not index user_id on its own.
create index if not exists team_members_user_id_idx on public.team_members using btree (user_id);
create index if not exists projects_team_id_idx on public.projects using btree (team_id);

-- 3. Enable RLS and reset grants on the existing tables.
alter table public.teams enable row level security;
alter table public.team_members enable row level security;
alter table public.projects enable row level security;

revoke all on table public.teams, public.team_members, public.projects from anon, authenticated;

-- Clients read teams, read and change membership (admins only, enforced by policy),
-- and manage projects. No client updates or deletes teams, and no client updates team_members.
grant select on table public.teams to authenticated;
grant select, insert, delete on table public.team_members to authenticated;
grant select, insert, update, delete on table public.projects to authenticated;

-- 4. Teams: members see their own team only.
create policy "Members can view their team"
on public.teams for select
to authenticated
using ( private.is_team_member(id) );

-- 5. Team members: members see their team's roster; only admins add or remove members.
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

-- 6. Projects: members read; only admins create, rename, or delete.
create policy "Members can view their team's projects"
on public.projects for select
to authenticated
using ( private.is_team_member(team_id) );

create policy "Admins can create their team's projects"
on public.projects for insert
to authenticated
with check ( private.is_team_admin(team_id) );

-- The using clause checks the existing row; with check checks the result,
-- so a project cannot be moved into a team the caller does not administer.
create policy "Admins can rename their team's projects"
on public.projects for update
to authenticated
using ( private.is_team_admin(team_id) )
with check ( private.is_team_admin(team_id) );

create policy "Admins can delete their team's projects"
on public.projects for delete
to authenticated
using ( private.is_team_admin(team_id) );
