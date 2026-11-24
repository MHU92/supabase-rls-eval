-- Migration: team-based RLS for teams, team_members, projects
-- Rule: members read their team's projects and roster; only admins write
-- projects and membership; no cross-team access.

-- 1. Helper functions (security definer, pinned search_path, break RLS recursion)
create schema if not exists private;

create or replace function private.is_team_member(p_team_id int)
returns boolean
language sql
security definer
set search_path = ''
stable
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
set search_path = ''
stable
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
grant usage on schema private to authenticated;
grant execute on function private.is_team_member(int) to authenticated;
grant execute on function private.is_team_admin(int) to authenticated;

-- 2. Index the membership lookups used by the policies
-- (primary key covers team_id first; user_id needs its own index)
create index if not exists team_members_user_id_idx
  on public.team_members using btree (user_id);

-- 3. Enable RLS and reset grants
alter table public.teams        enable row level security;
alter table public.team_members enable row level security;
alter table public.projects     enable row level security;

revoke all on table public.teams        from anon, authenticated;
revoke all on table public.team_members from anon, authenticated;
revoke all on table public.projects     from anon, authenticated;

grant select on table public.teams        to authenticated;
grant select, insert, update, delete on table public.team_members to authenticated;
grant select, insert, update, delete on table public.projects     to authenticated;

-- 4. teams: members see their own teams; admins may rename them
-- (no insert/delete policy: team creation/deletion is not part of the rule)
create policy "Members can view their teams"
on public.teams for select
to authenticated
using ( (select private.is_team_member(id)) );

create policy "Admins can rename their team"
on public.teams for update
to authenticated
using ( (select private.is_team_admin(id)) )
with check ( (select private.is_team_admin(id)) );

-- 5. team_members: members see their team's roster; admins add/remove members
create policy "Members can view their team roster"
on public.team_members for select
to authenticated
using ( (select private.is_team_member(team_id)) );

create policy "Admins can add members to their team"
on public.team_members for insert
to authenticated
with check ( (select private.is_team_admin(team_id)) );

create policy "Admins can update members of their team"
on public.team_members for update
to authenticated
using ( (select private.is_team_admin(team_id)) )
with check ( (select private.is_team_admin(team_id)) );

create policy "Admins can remove members from their team"
on public.team_members for delete
to authenticated
using ( (select private.is_team_admin(team_id)) );

-- 6. projects: members read; only admins create, rename, delete
create policy "Members can view their team's projects"
on public.projects for select
to authenticated
using ( (select private.is_team_member(team_id)) );

create policy "Admins can create team projects"
on public.projects for insert
to authenticated
with check ( (select private.is_team_admin(team_id)) );

create policy "Admins can rename team projects"
on public.projects for update
to authenticated
using ( (select private.is_team_admin(team_id)) )
with check ( (select private.is_team_admin(team_id)) );

create policy "Admins can delete team projects"
on public.projects for delete
to authenticated
using ( (select private.is_team_admin(team_id)) );

-- Index for project lookups by team
create index if not exists projects_team_id_idx
  on public.projects using btree (team_id);
